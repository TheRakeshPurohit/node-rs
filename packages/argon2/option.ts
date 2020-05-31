import * as fbb from 'flatbuffers'

import { argon2 } from './src/option_generated'

const option = new argon2.Options()

option.__init()
