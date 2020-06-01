import { randomBytes } from 'crypto'
import { promisify } from 'util'

import { locateBinding } from '@node-rs/helper'
import { flatbuffers } from 'flatbuffers'

import { argon2 } from './src/option_generated'

const bindings = require(locateBinding(__dirname, 'argon2'))

const randomBytesAsync = promisify(randomBytes)

export const Argon2Type = argon2.Argon2Type
export const Version = argon2.Version

export type Options = {
  associatedData?: Buffer
  hashLength?: number
  parallelism?: number
  memoryCost?: number
  secret?: Buffer
  timeCost?: number
  variant?: argon2.Argon2Type
  version?: argon2.Version
  salt?: Buffer
  saltLength?: number
}

export const defaults: Required<Omit<Options, 'salt'>> = {
  hashLength: 32,
  timeCost: 3,
  memoryCost: 4096,
  parallelism: 1,
  variant: Argon2Type.I,
  version: Version.Version10,
  associatedData: Buffer.alloc(0),
  secret: Buffer.alloc(0),
  saltLength: 16,
}

export function hash(plain: Buffer | string, options: Options & { raw: true }): Promise<Buffer>
export function hash(plain: Buffer | string, options?: Options & { raw?: false }): Promise<string>

export async function hash(
  input: string | Buffer,
  options: Options & { raw?: boolean } = {},
): Promise<Buffer | string> {
  const hashInput = Buffer.isBuffer(input) ? input : Buffer.from(input)
  const optionsBuilder = new flatbuffers.Builder(0)
  const adOffset = argon2.Options.createAssociatedDataVector(
    optionsBuilder,
    new Uint8Array((options.associatedData ?? defaults.associatedData).buffer),
  )
  const secretOffset = argon2.Options.createSecretVector(
    optionsBuilder,
    new Uint8Array((options.secret ?? defaults.secret).buffer),
  )

  argon2.Options.startOptions(optionsBuilder)
  argon2.Options.addAssociatedData(optionsBuilder, adOffset)
  argon2.Options.addHashLength(optionsBuilder, options.hashLength ?? defaults.hashLength)
  argon2.Options.addMemoryCost(optionsBuilder, options.memoryCost ?? defaults.memoryCost)
  argon2.Options.addParallelism(optionsBuilder, options.parallelism ?? defaults.parallelism)
  argon2.Options.addTimeCost(optionsBuilder, options.timeCost ?? defaults.timeCost)
  argon2.Options.addVariant(optionsBuilder, options.variant ?? defaults.variant)
  argon2.Options.addVersion(optionsBuilder, options.version ?? defaults.version)
  argon2.Options.addSecret(optionsBuilder, secretOffset)
  const opt = argon2.Options.endOptions(optionsBuilder)
  optionsBuilder.finish(opt)

  const buf = optionsBuilder.dataBuffer()
  const salt = options.salt ?? (await randomBytesAsync(options.saltLength ?? defaults.saltLength))

  return bindings.hash(hashInput, salt, buf.bytes().buffer)
}
