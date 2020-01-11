/**
 * @license
 * Copyright 2018-2020 Balena Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { BalenaSDK } from 'balena-sdk';
import * as Bluebird from 'bluebird';
import { stripIndent } from 'common-tags';
import Dockerode = require('dockerode');
import * as _ from 'lodash';
import { Composition } from 'resin-compose-parse';
import * as MultiBuild from 'resin-multibuild';
import { Readable } from 'stream';
import * as tar from 'tar-stream';

import { ExpectedError } from '../errors';
import { DeviceInfo } from './device/api';
import Logger = require('./logger');
import { exitWithExpectedError } from './patterns';

export interface RegistrySecrets {
	[registryAddress: string]: {
		username: string;
		password: string;
	};
}

/**
 * high-level function resolving a project and creating a composition out
 * of it in one go. if image is given, it'll create a default project for
 * that without looking for a project. falls back to creating a default
 * project if none is found at the given projectPath.
 */
export async function loadProject(
	logger: Logger,
	opts: import('./compose').ComposeOpts,
	image?: string,
): Promise<import('./compose').ComposeProject> {
	const dockerfilePath = await validateProjectDirectory(opts);
	const compose = await import('resin-compose-parse');
	const { createProject, resolveProject } = await import('./compose');
	let composeStr: string;

	logger.logDebug('Loading project...');

	if (image) {
		logger.logInfo(`Creating default composition with image: ${image}`);
		composeStr = compose.defaultComposition(image);
	} else {
		logger.logDebug('Resolving project...');
		try {
			composeStr = await resolveProject(opts.projectPath);
			if (dockerfilePath) {
				logger.logWarn(
					`Ignoring alternative dockerfile "${dockerfilePath}" because a docker-compose file exists`,
				);
			} else {
				logger.logInfo('Compose file detected');
			}
		} catch (e) {
			logger.logDebug(`Failed to resolve project: ${e}`);
			logger.logInfo(
				`Creating default composition with source: ${opts.projectPath}`,
			);
			composeStr = compose.defaultComposition(undefined, dockerfilePath);
		}
	}
	logger.logDebug('Creating project...');
	return createProject(opts.projectPath, composeStr, opts.projectName);
}

/**
 * Load the ".balena/balena.yml" file (or resin.yml, or yaml or json),
 * which contains "build metadata" for features like "build secrets" and
 * "build variables".
 * @returns Pair of metadata object and metadata file path
 */
export async function loadBuildMetatada(
	sourceDir: string,
): Promise<[MultiBuild.ParsedBalenaYml, string]> {
	const { fs } = await import('mz');
	const path = await import('path');
	let metadataPath = '';
	let rawString = '';

	outer: for (const fName of ['balena', 'resin']) {
		for (const fExt of ['yml', 'yaml', 'json']) {
			metadataPath = path.join(sourceDir, `.${fName}`, `${fName}.${fExt}`);
			try {
				rawString = await fs.readFile(metadataPath, 'utf8');
				break outer;
			} catch (err) {
				if (err.code === 'ENOENT') {
					// file not found, try the next name.extension combination
					continue;
				} else {
					throw err;
				}
			}
		}
	}
	if (!rawString) {
		return [{}, ''];
	}
	let buildMetadata: MultiBuild.ParsedBalenaYml;
	try {
		if (metadataPath.endsWith('json')) {
			buildMetadata = JSON.parse(rawString);
		} else {
			buildMetadata = require('js-yaml').safeLoad(rawString);
		}
	} catch (err) {
		return exitWithExpectedError(
			`Error parsing file "${metadataPath}":\n ${err.message}`,
		);
	}
	return [buildMetadata, metadataPath];
}

/**
 * Check whether the "build secrets" feature is being used and, if so,
 * verify that the target docker daemon is balenaEngine. If the
 * requirement is not satisfied, call exitWithExpectedError().
 * @param docker Dockerode instance
 * @param sourceDir Project directory where to find .balena/balena.yml
 */
export async function checkBuildSecretsRequirements(
	docker: Dockerode,
	sourceDir: string,
) {
	const [metaObj, metaFilename] = await loadBuildMetatada(sourceDir);
	if (metaObj && !_.isEmpty(metaObj['build-secrets'])) {
		const dockerUtils = await import('./docker');
		const isBalenaEngine = await dockerUtils.isBalenaEngine(docker);
		if (!isBalenaEngine) {
			exitWithExpectedError(stripIndent`
				The "build secrets" feature currently requires balenaEngine, but a standard Docker
				daemon was detected. Please use command-line options to specify the hostname and
				port number (or socket path) of a balenaEngine daemon, running on a balena device
				or a virtual machine with balenaOS. If the build secrets feature is not required,
				comment out or delete the 'build-secrets' entry in the file:
				"${metaFilename}"
				`);
		}
	}
}

export async function getRegistrySecrets(
	sdk: BalenaSDK,
	inputFilename?: string,
): Promise<RegistrySecrets> {
	const { fs } = await import('mz');
	const Path = await import('path');

	if (inputFilename != null) {
		return await parseRegistrySecrets(inputFilename);
	}

	const directory = await sdk.settings.get('dataDirectory');
	const potentialPaths = [
		Path.join(directory, 'secrets.yml'),
		Path.join(directory, 'secrets.yaml'),
		Path.join(directory, 'secrets.json'),
	];

	for (const path of potentialPaths) {
		if (await fs.exists(path)) {
			return await parseRegistrySecrets(path);
		}
	}

	return {};
}

async function parseRegistrySecrets(
	secretsFilename: string,
): Promise<RegistrySecrets> {
	const { fs } = await import('mz');
	try {
		let isYaml = false;
		if (/.+\.ya?ml$/i.test(secretsFilename)) {
			isYaml = true;
		} else if (!/.+\.json$/i.test(secretsFilename)) {
			throw new Error('Filename must end with .json, .yml or .yaml');
		}
		const raw = (await fs.readFile(secretsFilename)).toString();
		const registrySecrets = new MultiBuild.RegistrySecretValidator().validateRegistrySecrets(
			isYaml ? require('js-yaml').safeLoad(raw) : JSON.parse(raw),
		);
		MultiBuild.addCanonicalDockerHubEntry(registrySecrets);
		return registrySecrets;
	} catch (error) {
		return exitWithExpectedError(
			`Error validating registry secrets file "${secretsFilename}":\n${
				error.message
			}`,
		);
	}
}

/**
 * Validate the compose-specific command-line options defined in compose.coffee.
 * This function is meant to be called very early on to validate users' input,
 * before any project loading / building / deploying.
 */
export async function validateComposeOptions(
	sdk: BalenaSDK,
	options: { [opt: string]: any },
) {
	options['registry-secrets'] = await getRegistrySecrets(
		sdk,
		options['registry-secrets'],
	);
}

/**
 * Create a BuildTask array of "resolved build tasks" by calling multibuild
 * .splitBuildStream() and performResolution(), and add build stream error
 * handlers and debug logging.
 * Both `balena build` and `balena deploy` call this function.
 */
export async function makeBuildTasks(
	composition: Composition,
	tarStream: Readable,
	deviceInfo: DeviceInfo,
	logger: Logger,
): Promise<MultiBuild.BuildTask[]> {
	const buildTasks = await MultiBuild.splitBuildStream(composition, tarStream);

	logger.logDebug('Found build tasks:');
	_.each(buildTasks, task => {
		let infoStr: string;
		if (task.external) {
			infoStr = `image pull [${task.imageName}]`;
		} else {
			infoStr = `build [${task.context}]`;
		}
		logger.logDebug(`    ${task.serviceName}: ${infoStr}`);
	});

	logger.logDebug(
		`Resolving services with [${deviceInfo.deviceType}|${deviceInfo.arch}]`,
	);

	await performResolution(buildTasks, deviceInfo);

	logger.logDebug('Found project types:');
	_.each(buildTasks, task => {
		if (task.external) {
			logger.logDebug(`    ${task.serviceName}: External image`);
		} else {
			logger.logDebug(`    ${task.serviceName}: ${task.projectType}`);
		}
	});

	return buildTasks;
}

async function performResolution(
	tasks: MultiBuild.BuildTask[],
	deviceInfo: DeviceInfo,
): Promise<MultiBuild.BuildTask[]> {
	const { cloneTarStream } = require('tar-utils');

	return await new Promise<MultiBuild.BuildTask[]>((resolve, reject) => {
		const buildTasks = MultiBuild.performResolution(
			tasks,
			deviceInfo.arch,
			deviceInfo.deviceType,
			{ error: [reject] },
		);
		// Do one task at a time (Bluebird.each instead of Bluebird.all)
		// in order to reduce peak memory usage. Resolves to buildTasks.
		Bluebird.each(buildTasks, buildTask => {
			// buildStream is falsy for "external" tasks (image pull)
			if (!buildTask.buildStream) {
				return buildTask;
			}
			// Consume each task.buildStream in order to trigger the
			// resolution events that define fields like:
			//     task.dockerfile, task.dockerfilePath,
			//     task.projectType, task.resolved
			// This mimics what is currently done in `resin-builder`.
			return cloneTarStream(buildTask.buildStream).then(
				(clonedStream: tar.Pack) => {
					buildTask.buildStream = clonedStream;
					if (!buildTask.external && !buildTask.resolved) {
						throw new Error(
							`Project type for service "${
								buildTask.serviceName
							}" could not be determined. Missing a Dockerfile?`,
						);
					}
					return buildTask;
				},
			);
		}).then(resolve, reject);
	});
}

/**
 * Enforce that, for example, if 'myProject/MyDockerfile.template' is specified
 * as an alternativate Dockerfile name, then 'myProject/MyDockerfile' must not
 * exist.
 * Return the tar stream path (Posix, normalized) for the given dockerfilePath.
 * For example, on Windows, given a dockerfilePath of 'foo\..\bar\Dockerfile',
 * return 'bar/Dockerfile'. On Linux, given './bar/Dockerfile', return 'bar/Dockerfile'.
 *
 * @param projectPath The project source folder (-s command-line option)
 * @param dockerfilePath The alternative Dockerfile specified by the user
 * @return A normalized posix representation of dockerfilePath
 */
async function validateSpecifiedDockerfile(
	projectPath: string,
	dockerfilePath: string,
): Promise<string> {
	const fs = (await import('mz')).fs;
	const { isAbsolute, join, normalize, parse } = await import('path');
	const { contains, toNativePath, toPosixPath } = MultiBuild.PathUtils;

	const nativeProjectPath = normalize(projectPath);
	const nativeDockerfilePath = normalize(toNativePath(dockerfilePath));

	// reminder: native windows paths may start with a drive specificaton,
	// e.g. 'C:\absolute' or 'C:relative'.
	if (isAbsolute(nativeDockerfilePath)) {
		throw new ExpectedError(stripIndent`
			Error: the specified Dockerfile cannot be an absolute path. The path must be
			relative to, and not a parent folder of, the project's source folder.
			Specified dockerfile: "${nativeDockerfilePath}"
			Project's source folder: "${nativeProjectPath}"
		`);
	}

	// note that path.normalize('a/../../b') results in '../b'
	if (nativeDockerfilePath.startsWith('..')) {
		throw new ExpectedError(stripIndent`
			Error: the specified Dockerfile cannot be in a parent folder of the project's
			source folder. Note that the path should be relative to the project's source
			folder, not the current folder.
			Specified dockerfile: "${nativeDockerfilePath}"
			Project's source folder: "${nativeProjectPath}"
		`);
	}

	console.error(`join(${nativeProjectPath}, ${nativeDockerfilePath})`);
	const fullDockerfilePath = join(nativeProjectPath, nativeDockerfilePath);

	if (!(await fs.exists(fullDockerfilePath))) {
		throw new ExpectedError(stripIndent`
			Error: file not found: "${fullDockerfilePath}"
		`);
	}

	if (!contains(nativeProjectPath, fullDockerfilePath)) {
		throw new ExpectedError(stripIndent`
			Error: the specified Dockerfile must be in a subfolder of the source folder:
			Specified dockerfile: "${fullDockerfilePath}"
			Project's source folder: "${nativeProjectPath}"
		`);
	}

	const { dir, ext, name } = parse(fullDockerfilePath);
	if (ext) {
		const nativePathMinusExt = join(dir, name);
		if (await fs.exists(nativePathMinusExt)) {
			throw new ExpectedError(stripIndent`
				Error: "${name}" exists on the same folder as "${nativeDockerfilePath}".
				When an alternative Dockerfile name is specified, a file with the same base name
				(minus the file extension) must not exist in the same folder. This is because
				the base name file will be auto generated and added to the tar stream that is
				sent to balenaEngine or the Docker daemon, resulting in duplicate Dockerfiles
				and undefined behavior.
			`);
		}
	}
	return toPosixPath(nativeDockerfilePath);
}

export async function validateProjectDirectory(
	opts: import('./compose').ComposeOpts,
): Promise<string> {
	console.error('validateProjectDirectory');

	if (opts.dockerfilePath) {
		const dockerfilePath = await validateSpecifiedDockerfile(
			opts.projectPath,
			opts.dockerfilePath,
		);
		console.error(`dockerfilePath: "${dockerfilePath}"`);
		throw new ExpectedError('foo');
		return dockerfilePath;
	}

	const { join } = await import('path');
	const fs = (await import('mz')).fs;
	const files = await fs.readdir(opts.projectPath);
	console.log(`files: ${files}`);
	const projectMatch = (file: string) =>
		/^(Dockerfile|Dockerfile\.\S+|docker-compose.ya?ml|package.json)$/.test(
			file,
		);
	if (!_.some(files, projectMatch)) {
		throw new ExpectedError(stripIndent`
			Error: no "Dockerfile[.*]", "docker-compose.yml" or "package.json" file
			found in project source folder "${opts.projectPath}"
		`);
	}
	if (!opts.noComposeCheck) {
		const checkCompose = async (folder: string) => {
			return _.some(
				await Promise.all([
					fs.exists(join(folder, 'docker-compose.yml')),
					fs.exists(join(folder, 'docker-compose.yaml')),
				]),
			);
		};
		const [hasCompose, hasParentCompose] = await Promise.all([
			checkCompose(opts.projectPath),
			checkCompose(join(opts.projectPath, '..')),
		]);
		if (!hasCompose && hasParentCompose) {
			Logger.getLogger().logWarn(stripIndent`
				"docker-compose.y[a]ml" file found in parent directory: please check that the
				correct folder is being built / pushed. (Suppress with '--nocompose-check'.)
			`);
		}
	}

	throw new ExpectedError('bar');
	return opts.dockerfilePath || '';
}
