###*
# @license
# Copyright 2017-2019 Balena Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

Promise = require('bluebird')
path = require('path')

exports.appendProjectOptions = appendProjectOptions = (opts) ->
	opts.concat [
		{
			signature: 'projectName'
			parameter: 'projectName'
			description: 'Specify an alternate project name; default is the directory name'
			alias: 'n'
		},
	]

exports.appendOptions = (opts) ->
	appendProjectOptions(opts).concat [
		{
			signature: 'dockerfile'
			parameter: 'Dockerfile'
			description: 'Alternative Dockerfile name/path, relative to the source folder'
		},
		{
			signature: 'emulated'
			description: 'Run an emulated build using Qemu'
			boolean: true
			alias: 'e'
		},
		{
			signature: 'logs'
			description: 'Display full log output'
			boolean: true
		},
		{
			signature: 'nocompose-check'
			description: 'Disable check for \'docker-compose.yml\' file in parent source folder'
			boolean: true
		},
		{
			signature: 'registry-secrets'
			alias: 'R'
			parameter: 'secrets.yml|.json'
			description: 'Path to a YAML or JSON file with passwords for a private Docker registry'
		},
	]

exports.generateOpts = (options) ->
	fs = require('mz/fs')
	fs.realpath(options.source || '.').then (projectPath) ->
		projectName: options.projectName
		projectPath: projectPath
		inlineLogs: !!options.logs
		dockerfilePath: options.dockerfile
		noComposeCheck: options['nocompose-check']

compositionFileNames = [
	'docker-compose.yml'
	'docker-compose.yaml'
]

# look into the given directory for valid compose files and return
# the contents of the first one found.
exports.resolveProject = (rootDir) ->
	fs = require('mz/fs')
	Promise.any compositionFileNames.map (filename) ->
		fs.readFile(path.join(rootDir, filename), 'utf-8')

# Parse the given composition and return a structure with info. Input is:
#  - composePath: the *absolute* path to the directory containing the compose file
#  - composeStr: the contents of the compose file, as a string
exports.createProject = (composePath, composeStr, projectName = null) ->
	yml = require('js-yaml')
	compose = require('resin-compose-parse')

	# both methods below may throw.
	composition = yml.safeLoad(composeStr, schema: yml.FAILSAFE_SCHEMA)
	composition = compose.normalize(composition)

	projectName ?= path.basename(composePath)
	descriptors = compose.parse(composition).map (descr) ->
		# generate an image name based on the project and service names
		# if one is not given and the service requires a build
		if descr.image.context? and not descr.image.tag?
			descr.image.tag = [ projectName, descr.serviceName ].join('_').toLowerCase()
		return descr
	return {
		path: composePath,
		name: projectName,
		composition,
		descriptors
	}

exports.tarDirectory = tarDirectory = (dir, preFinalizeCallback = null) ->
	tar = require('tar-stream')
	klaw = require('klaw')
	path = require('path')
	fs = require('mz/fs')
	streamToPromise = require('stream-to-promise')
	{ FileIgnorer } = require('./ignore')
	{ toPosixPath } = require('resin-multibuild').PathUtils

	getFiles = ->
		streamToPromise(klaw(dir))
		.filter((item) -> not item.stats.isDirectory())
		.map((item) -> item.path)

	ignore = new FileIgnorer(dir)
	pack = tar.pack()
	getFiles(dir)
	.each (file) ->
		type = ignore.getIgnoreFileType(path.relative(dir, file))
		if type?
			ignore.addIgnoreFile(file, type)
	.filter(ignore.filter)
	.map (file) ->
		relPath = path.relative(path.resolve(dir), file)
		Promise.join relPath, fs.stat(file), fs.readFile(file),
			(filename, stats, data) ->
				pack.entry({ name: toPosixPath(filename), size: stats.size, mode: stats.mode }, data)
	.then ->
		preFinalizeCallback?(pack)
	.then ->
		pack.finalize()
		return pack

truncateString = (str, len) ->
	return str if str.length < len
	str = str.slice(0, len)
	# return everything up to the last line. this is a cheeky way to avoid
	# having to deal with splitting the string midway through some special
	# character sequence.
	return str.slice(0, str.lastIndexOf('\n'))

LOG_LENGTH_MAX = 512 * 1024 # 512KB

exports.buildProject = (
	docker, logger,
	projectPath, projectName, composition,
	arch, deviceType,
	emulated, buildOpts,
	inlineLogs
) ->
	_ = require('lodash')
	humanize = require('humanize')
	compose = require('resin-compose-parse')
	builder = require('resin-multibuild')
	transpose = require('docker-qemu-transpose')
	{ BALENA_ENGINE_TMP_PATH } = require('../config')
	{ checkBuildSecretsRequirements, makeBuildTasks } = require('./compose_ts')
	qemu = require('./qemu-ts')
	{ toPosixPath } = builder.PathUtils

	logger.logInfo("Building for #{arch}/#{deviceType}")

	imageDescriptors = compose.parse(composition)
	imageDescriptorsByServiceName = _.keyBy(imageDescriptors, 'serviceName')

	if inlineLogs
		renderer = new BuildProgressInline(logger.streams['build'], imageDescriptors)
	else
		tty = require('./tty')(process.stdout)
		renderer = new BuildProgressUI(tty, imageDescriptors)
	renderer.start()

	Promise.resolve(checkBuildSecretsRequirements(docker, projectPath))
	.then -> qemu.installQemuIfNeeded(emulated, logger, arch, docker)
	.tap (needsQemu) ->
		return if not needsQemu
		logger.logInfo('Emulation is enabled')
		# Copy qemu into all build contexts
		Promise.map imageDescriptors, (d) ->
			return if not d.image.context? # external image
			return qemu.copyQemu(path.join(projectPath, d.image.context), arch)
	.then (needsQemu) ->
		# Tar up the directory, ready for the build stream
		tarDirectory(projectPath)
		.then (tarStream) ->
			Promise.resolve(makeBuildTasks(composition, tarStream, { arch, deviceType }, logger))
		.map (task) ->
			d = imageDescriptorsByServiceName[task.serviceName]

			# multibuild parses the composition internally so any tags we've
			# set before are lost; re-assign them here
			task.tag ?= [ projectName, task.serviceName ].join('_').toLowerCase()
			if d.image.context?
				d.image.tag = task.tag

			# configure build opts appropriately
			task.dockerOpts ?= {}
			_.merge(task.dockerOpts, buildOpts, { t: task.tag })
			if d.image.context?.args?
				task.dockerOpts.buildargs ?= {}
				_.merge(task.dockerOpts.buildargs, d.image.context.args)

			# Get the service-specific log stream
			# Caveat: `multibuild.BuildTask` defines no `logStream` property
			# but it's convenient to store it there; it's JS ultimately.
			task.logStream = renderer.streams[task.serviceName]
			task.logBuffer = []

			# Setup emulation if needed
			return [ task, null ] if task.external or not needsQemu
			binPath = qemu.qemuPathInContext(path.join(projectPath, task.context))
			transpose.transposeTarStream task.buildStream,
				hostQemuPath: toPosixPath(binPath)
				containerQemuPath: "/tmp/#{qemu.QEMU_BIN_NAME}"
				qemuFileMode: 0o555
			.then (stream) ->
				task.buildStream = stream
			.return([ task, binPath ])
	.map ([ task, qemuPath ]) ->
		Promise.resolve(task).tap (task) ->
			captureStream = buildLogCapture(task.external, task.logBuffer)

			if task.external
				# External image -- there's no build to be performed,
				# just follow pull progress.
				captureStream.pipe(task.logStream)
				task.progressHook = pullProgressAdapter(captureStream)
			else
				task.streamHook = (stream) ->
					stream = createLogStream(stream)
					if qemuPath?
						buildThroughStream = transpose.getBuildThroughStream
							hostQemuPath: toPosixPath(qemuPath)
							containerQemuPath: "/tmp/#{qemu.QEMU_BIN_NAME}"
						rawStream = stream.pipe(buildThroughStream)
					else
						rawStream = stream
					# `stream` sends out raw strings in contrast to `task.progressHook`
					# where we're given objects. capture these strings as they come
					# before we parse them.
					rawStream
					.pipe(dropEmptyLinesStream())
					.pipe(captureStream)
					.pipe(buildProgressAdapter(inlineLogs))
					.pipe(task.logStream)
	.then (tasks) ->
		logger.logDebug 'Prepared tasks; building...'
		Promise.resolve(builder.performBuilds(tasks, docker, BALENA_ENGINE_TMP_PATH))
		.map (builtImage) ->
			if not builtImage.successful
				builtImage.error.serviceName = builtImage.serviceName
				throw builtImage.error

			d = imageDescriptorsByServiceName[builtImage.serviceName]
			task = _.find(tasks, serviceName: builtImage.serviceName)

			image =
				serviceName: d.serviceName
				name: d.image.tag ? d.image
				logs: truncateString(task.logBuffer.join('\n'), LOG_LENGTH_MAX)
				props:
					dockerfile: builtImage.dockerfile
					projectType: builtImage.projectType

			# Times here are timestamps, so test whether they're null
			# before creating a date out of them, as `new Date(null)`
			# creates a date representing UNIX time 0.
			if (startTime = builtImage.startTime)
				image.props.startTime = new Date(startTime)
			if (endTime = builtImage.endTime)
				image.props.endTime = new Date(endTime)
			docker.getImage(image.name).inspect().get('Size').then (size) ->
				image.props.size = size
			.return(image)
		.tap (images) ->
			summary = _(images).map ({ serviceName, props }) ->
				[ serviceName, "Image size: #{humanize.filesize(props.size)}" ]
			.fromPairs()
			.value()
			renderer.end(summary)
	.finally(renderer.end)

createRelease = (apiEndpoint, auth, userId, appId, composition) ->
	_ = require('lodash')
	crypto = require('crypto')
	releaseMod = require('resin-release')

	client = releaseMod.createClient({ apiEndpoint, auth })

	releaseMod.create
		client: client
		user: userId
		application: appId
		composition: composition
		source: 'local'
		commit: crypto.pseudoRandomBytes(16).toString('hex').toLowerCase()
	.then ({ release, serviceImages }) ->
		release = _.omit(release, [
			'created_at'
			'belongs_to__application'
			'is_created_by__user'
			'__metadata'
		])
		serviceImages = _.mapValues serviceImages, (serviceImage) ->
			_.omit(serviceImage, [
				'created_at'
				'is_a_build_of__service'
				'__metadata'
			])
		return { client, release, serviceImages }

tagServiceImages = (docker, images, serviceImages) ->
	Promise.map images, (d) ->
		serviceImage = serviceImages[d.serviceName]
		imageName = serviceImage.is_stored_at__image_location
		# coffeelint: disable-next-line=check_scope ("Variable is assigned to but never read")
		[ _match, registry, repo, tag = 'latest' ] = /(.*?)\/(.*?)(?::([^/]*))?$/.exec(imageName)
		name = "#{registry}/#{repo}"
		docker.getImage(d.name).tag({ repo: name, tag, force: true })
		.then ->
			docker.getImage("#{name}:#{tag}")
		.then (localImage) ->
			serviceName: d.serviceName
			serviceImage: serviceImage
			localImage: localImage
			registry: registry
			repo: repo
			logs: d.logs
			props: d.props


getPreviousRepos = (sdk, docker, logger, appID) ->
	sdk.pine.get(
		resource: 'release'
		options:
			$filter:
				belongs_to__application: appID
				status: 'success'
			$select:
				[ 'id' ]
			$expand:
				contains__image:
					$expand: 'image'
			$orderby: 'id desc'
			$top: 1
	)
	.then (release) ->
		# grab all images from the latest release, return all image locations in the registry
		if release?.length > 0
			images = release[0].contains__image
			Promise.map images, (d) ->
				imageName = d.image[0].is_stored_at__image_location
				docker.getRegistryAndName(imageName)
				.then ( registry ) ->
					logger.logDebug("Requesting access to previously pushed image repo (#{registry.imageName})")
					return registry.imageName
	.catch (e) ->
		logger.logDebug("Failed to access previously pushed image repo: #{e}")

authorizePush = (sdk, logger, tokenAuthEndpoint, registry, images, previousRepos) ->
	_ = require('lodash')

	if not _.isArray(images)
		images = [ images ]

	images.push previousRepos...
	sdk.request.send
		baseUrl: tokenAuthEndpoint
		url: '/auth/v1/token'
		qs:
			service: registry
			scope: images.map (repo) ->
				"repository:#{repo}:pull,push"
	.get('body')
	.get('token')
	.catchReturn({})

pushAndUpdateServiceImages = (docker, token, images, afterEach) ->
	chalk = require('chalk')
	{ DockerProgress } = require('docker-progress')
	{ retry } = require('./helpers')
	tty = require('./tty')(process.stdout)

	opts = { authconfig: registrytoken: token }

	progress = new DockerProgress(dockerToolbelt: docker)
	renderer = pushProgressRenderer(tty, chalk.blue('[Push]') + '    ')
	reporters = progress.aggregateProgress(images.length, renderer)

	Promise.using tty.cursorHidden(), ->
		Promise.map images, ({ serviceImage, localImage, props, logs }, index) ->
			Promise.join(
				localImage.inspect().get('Size')
				retry(
					-> progress.push(localImage.name, reporters[index], opts)
					3  # `times` - retry 3 times
					localImage.name  # `label` included in retry log messages
					2000  # `delayMs` - wait 2 seconds before the 1st retry
					1.4  # `backoffScaler` - wait multiplier for each retry
				).finally(renderer.end)
				(size, digest) ->
					serviceImage.image_size = size
					serviceImage.content_hash = digest
					serviceImage.build_log = logs
					serviceImage.dockerfile = props.dockerfile
					serviceImage.project_type = props.projectType
					serviceImage.start_timestamp = props.startTime if props.startTime
					serviceImage.end_timestamp = props.endTime if props.endTime
					serviceImage.push_timestamp = new Date()
					serviceImage.status = 'success'
			)
			.tapCatch (e) ->
				serviceImage.error_message = '' + e
				serviceImage.status = 'failed'
			.finally ->
				afterEach?(serviceImage, props)

exports.deployProject = (
	docker, logger,
	composition, images,
	appId, userId, auth,
	apiEndpoint,
	skipLogUpload
) ->
	_ = require('lodash')
	chalk = require('chalk')
	releaseMod = require('resin-release')
	tty = require('./tty')(process.stdout)

	prefix = chalk.cyan('[Info]') + '    '
	spinner = createSpinner()
	runloop = runSpinner(tty, spinner, "#{prefix}Creating release...")

	createRelease(apiEndpoint, auth, userId, appId, composition)
	.finally(runloop.end)
	.then ({ client, release, serviceImages }) ->
		logger.logDebug('Tagging images...')
		tagServiceImages(docker, images, serviceImages)
		.tap (images) ->
			logger.logDebug('Authorizing push...')
			sdk = require('balena-sdk').fromSharedOptions()
			getPreviousRepos(sdk, docker, logger, appId)
			.then (previousRepos) ->
				authorizePush(sdk, logger, apiEndpoint, images[0].registry, _.map(images, 'repo'), previousRepos)
			.then (token) ->
				logger.logInfo('Pushing images to registry...')
				pushAndUpdateServiceImages docker, token, images, (serviceImage) ->
					logger.logDebug("Saving image #{serviceImage.is_stored_at__image_location}")
					if skipLogUpload
						delete serviceImage.build_log
					releaseMod.updateImage(client, serviceImage.id, serviceImage)
			.finally ->
				logger.logDebug('Untagging images...')
				Promise.map images, ({ localImage }) ->
					localImage.remove()
		.then ->
			release.status = 'success'
		.tapCatch ->
			release.status = 'failed'
		.finally ->
			runloop = runSpinner(tty, spinner, "#{prefix}Saving release...")
			release.end_timestamp = new Date()
			releaseMod.updateRelease(client, release.id, release)
			.finally(runloop.end)
		.return(release)

# utilities

renderProgressBar = (percentage, stepCount) ->
	_ = require('lodash')
	percentage = _.clamp(percentage, 0, 100)
	barCount = stepCount * percentage // 100
	spaceCount = stepCount - barCount
	bar = "[#{_.repeat('=', barCount)}>#{_.repeat(' ', spaceCount)}]"
	return "#{bar} #{_.padStart(percentage, 3)}%"

pushProgressRenderer = (tty, prefix) ->
	fn = (e) ->
		{ error, percentage } = e
		throw new Error(error) if error?
		bar = renderProgressBar(percentage, 40)
		tty.replaceLine("#{prefix}#{bar}\r")
	fn.end = ->
		tty.clearLine()
	return fn

createLogStream = (input) ->
	split = require('split')
	stripAnsi = require('strip-ansi-stream')
	return input.pipe(stripAnsi()).pipe(split())

dropEmptyLinesStream = ->
	through = require('through2')
	through (data, enc, cb) ->
		str = data.toString('utf-8')
		@push(str) if str.trim()
		cb()

buildLogCapture = (objectMode, buffer) ->
	through = require('through2')

	through { objectMode }, (data, enc, cb) ->
		# data from pull stream
		if data.error
			buffer.push("#{data.error}")
		else if data.progress and data.status
			buffer.push("#{data.progress}% #{data.status}")
		else if data.status
			buffer.push("#{data.status}")

		# data from build stream
		else
			buffer.push(data)

		cb(null, data)

buildProgressAdapter = (inline) ->
	through = require('through2')

	stepRegex = /^\s*Step\s+(\d+)\/(\d+)\s*: (.+)$/

	[ step, numSteps, progress ] = [ null, null, undefined ]

	through { objectMode: true }, (str, enc, cb) ->
		return cb(null, str) if not str?

		if inline
			return cb(null, { status: str })

		if /^Successfully tagged /.test(str)
			progress = undefined
		else
			if (match = stepRegex.exec(str))
				step = match[1]
				numSteps ?= match[2]
				str = match[3]
			if step?
				str = "Step #{step}/#{numSteps}: #{str}"
				progress = parseInt(step, 10) * 100 // parseInt(numSteps, 10)

		cb(null, { status: str, progress })

pullProgressAdapter = (outStream) ->
	return ({ status, id, percentage, error, errorDetail }) ->
		if status?
			status = status.replace(/^Status: /, '')
		if id?
			status = "#{id}: #{status}"
		if percentage is 100
			percentage = undefined
		outStream.write
			status: status
			progress: percentage
			error: errorDetail?.message ? error

createSpinner = ->
	chars = '|/-\\'
	index = 0
	-> chars[(index++) % chars.length]

runSpinner = (tty, spinner, msg) ->
	runloop = createRunLoop ->
		tty.clearLine()
		tty.writeLine("#{msg} #{spinner()}")
		tty.cursorUp()
	runloop.onEnd = ->
		tty.clearLine()
		tty.writeLine(msg)
	return runloop

createRunLoop = (tick) ->
	timerId = setInterval(tick, 1000 / 10)
	runloop = {
		onEnd: ->
		end: ->
			clearInterval(timerId)
			runloop.onEnd()
	}
	return runloop

class BuildProgressUI
	constructor: (tty, descriptors) ->
		_ = require('lodash')
		chalk = require('chalk')
		through = require('through2')

		eventHandler = @_handleEvent
		services = _.map(descriptors, 'serviceName')

		streams = _(services).map (service) ->
			stream = through.obj (event, _enc, cb) ->
				eventHandler(service, event)
				cb()
			stream.pipe(tty.stream, end: false)
			[ service, stream ]
		.fromPairs()
		.value()

		@_tty = tty
		@_serviceToDataMap = {}
		@_services = services

		# Logger magically prefixes the log line with [Build] etc., but it doesn't
		# work well with the spinner we're also showing. Manually build the prefix
		# here and bypass the logger.
		prefix = chalk.blue('[Build]') + '   '

		offset = 10 # account for escape sequences inserted for colouring
		@_prefixWidth = offset + prefix.length + _.max(_.map(services, 'length'))
		@_prefix = prefix

		# these are to handle window wrapping
		@_maxLineWidth = null
		@_lineWidths = []

		@_startTime = null
		@_ended = false
		@_cancelled = false
		@_spinner = createSpinner()

		@streams = streams

	_handleEvent: (service, event) =>
		@_serviceToDataMap[service] = event

	_handleInterrupt: =>
		@_cancelled = true
		@end()
		process.exit(130) # 128 + SIGINT

	start: =>
		process.on('SIGINT', @_handleInterrupt)
		@_tty.hideCursor()
		@_services.forEach (service) =>
			@streams[service].write({ status: 'Preparing...' })
		@_runloop = createRunLoop(@_display)
		@_startTime = Date.now()

	end: (summary = null) =>
		return if @_ended
		@_ended = true
		process.removeListener('SIGINT', @_handleInterrupt)
		@_runloop.end()
		@_runloop = null

		@_clear()
		@_renderStatus(true)
		@_renderSummary(summary ? @_getServiceSummary())
		@_tty.showCursor()

	_display: =>
		@_clear()
		@_renderStatus()
		@_renderSummary(@_getServiceSummary())
		@_tty.cursorUp(@_services.length + 1) # for status line

	_clear: ->
		@_tty.deleteToEnd()
		@_maxLineWidth = @_tty.currentWindowSize().width

	_getServiceSummary: ->
		_ = require('lodash')

		services = @_services
		serviceToDataMap = @_serviceToDataMap

		_(services).map (service) ->
			{ status, progress, error } = serviceToDataMap[service] ? {}
			if error
				return "#{error}"
			else if progress
				bar = renderProgressBar(progress, 20)
				return "#{bar} #{status}" if status
				return "#{bar}"
			else if status
				return "#{status}"
			else
				return 'Waiting...'
		.map (data, index) ->
			[ services[index], data ]
		.fromPairs()
		.value()

	_renderStatus: (end = false) ->
		moment = require('moment')
		require('moment-duration-format')(moment)

		@_tty.clearLine()
		@_tty.write(@_prefix)
		if end and @_cancelled
			@_tty.writeLine('Build cancelled')
		else if end
			serviceCount = @_services.length
			serviceStr = if serviceCount is 1 then '1 service' else "#{serviceCount} services"
			runTime = Date.now() - @_startTime
			durationStr = moment.duration(runTime // 1000, 'seconds').format()
			@_tty.writeLine("Built #{serviceStr} in #{durationStr}")
		else
			@_tty.writeLine("Building services... #{@_spinner()}")

	_renderSummary: (serviceToStrMap) ->
		_ = require('lodash')
		chalk = require('chalk')
		truncate = require('cli-truncate')
		strlen = require('string-width')

		@_services.forEach (service, index) =>
			str = _.padEnd(@_prefix + chalk.bold(service), @_prefixWidth)
			str += serviceToStrMap[service]
			if @_maxLineWidth?
				str = truncate(str, @_maxLineWidth)
			@_lineWidths[index] = strlen(str)

			@_tty.clearLine()
			@_tty.writeLine(str)

class BuildProgressInline
	constructor: (outStream, descriptors) ->
		_ = require('lodash')
		through = require('through2')

		services = _.map(descriptors, 'serviceName')
		eventHandler = @_renderEvent
		streams = _(services).map (service) ->
			stream = through.obj (event, _enc, cb) ->
				eventHandler(service, event)
				cb()
			stream.pipe(outStream, end: false)
			[ service, stream ]
		.fromPairs()
		.value()

		offset = 10 # account for escape sequences inserted for colouring
		@_prefixWidth = offset + _.max(_.map(services, 'length'))
		@_outStream = outStream
		@_services = services
		@_startTime = null
		@_ended = false

		@streams = streams

	start: =>
		@_outStream.write('Building services...\n')
		@_services.forEach (service) =>
			@streams[service].write({ status: 'Preparing...' })
		@_startTime = Date.now()

	end: (summary = null) =>
		moment = require('moment')
		require('moment-duration-format')(moment)

		return if @_ended
		@_ended = true

		if summary?
			@_services.forEach (service) =>
				@_renderEvent(service, summary[service])

		if @_cancelled
			@_outStream.write('Build cancelled\n')
		else
			serviceCount = @_services.length
			serviceStr = if serviceCount is 1 then '1 service' else "#{serviceCount} services"
			runTime = Date.now() - @_startTime
			durationStr = moment.duration(runTime // 1000, 'seconds').format()
			@_outStream.write("Built #{serviceStr} in #{durationStr}\n")

	_renderEvent: (service, event) =>
		_ = require('lodash')
		chalk = require('chalk')

		str = do ->
			{ status, error } = event
			if error
				return "#{error}"
			else if status
				return "#{status}"
			else
				return 'Waiting...'

		prefix = _.padEnd(chalk.bold(service), @_prefixWidth)
		@_outStream.write(prefix)
		@_outStream.write(str)
		@_outStream.write('\n')
