/* eslint-disable */
/* prettier-ignore */

/* auto-generated by NAPI-RS */

const __nodeFs = require('node:fs')
const __nodePath = require('node:path')
const { WASI: __nodeWASI } = require('node:wasi')
const { Worker } = require('node:worker_threads')

const {
  instantiateNapiModuleSync: __emnapiInstantiateNapiModuleSync,
  getDefaultContext: __emnapiGetDefaultContext,
  createOnMessage: __wasmCreateOnMessageForFsProxy,
} = require('@napi-rs/wasm-runtime')

const __rootDir = __nodePath.parse(process.cwd()).root

const __wasi = new __nodeWASI({
  version: 'preview1',
  env: process.env,
  preopens: {
    [__rootDir]: __rootDir,
  }
})

const __emnapiContext = __emnapiGetDefaultContext()

const __sharedMemory = new WebAssembly.Memory({
  initial: 4000,
  maximum: 65536,
  shared: true,
})

let __wasmFilePath = __nodePath.join(__dirname, 'jieba.wasm32-wasi.wasm')
const __wasmDebugFilePath = __nodePath.join(__dirname, 'jieba.wasm32-wasi.debug.wasm')

if (__nodeFs.existsSync(__wasmDebugFilePath)) {
  __wasmFilePath = __wasmDebugFilePath
} else if (!__nodeFs.existsSync(__wasmFilePath)) {
  try {
    __wasmFilePath = __nodePath.resolve('@node-rs/jieba-wasm32-wasi')
  } catch {
    throw new Error('Cannot find jieba.wasm32-wasi.wasm file, and @node-rs/jieba-wasm32-wasi package is not installed.')
  }
}

const { instance: __napiInstance, module: __wasiModule, napiModule: __napiModule } = __emnapiInstantiateNapiModuleSync(__nodeFs.readFileSync(__wasmFilePath), {
  context: __emnapiContext,
  asyncWorkPoolSize: (function() {
    const threadsSizeFromEnv = Number(process.env.NAPI_RS_ASYNC_WORK_POOL_SIZE ?? process.env.UV_THREADPOOL_SIZE)
    // NaN > 0 is false
    if (threadsSizeFromEnv > 0) {
      return threadsSizeFromEnv
    } else {
      return 4
    }
  })(),
  wasi: __wasi,
  onCreateWorker() {
    const worker = new Worker(__nodePath.join(__dirname, 'wasi-worker.mjs'), {
      env: process.env,
      execArgv: ['--experimental-wasi-unstable-preview1'],
    })
    worker.onmessage = ({ data }) => {
      __wasmCreateOnMessageForFsProxy(__nodeFs)(data)
    }
    return worker
  },
  overwriteImports(importObject) {
    importObject.env = {
      ...importObject.env,
      ...importObject.napi,
      ...importObject.emnapi,
      memory: __sharedMemory,
    }
    return importObject
  },
  beforeInit({ instance }) {
    __napi_rs_initialize_modules(instance)
  }
})

function __napi_rs_initialize_modules(__napiInstance) {
  __napiInstance.exports['__napi_register__load_0']?.()
  __napiInstance.exports['__napi_register__load_dict_1']?.()
  __napiInstance.exports['__napi_register__cut_2']?.()
  __napiInstance.exports['__napi_register__cut_all_3']?.()
  __napiInstance.exports['__napi_register__cut_for_search_4']?.()
  __napiInstance.exports['__napi_register__TaggedWord_struct_5']?.()
  __napiInstance.exports['__napi_register__tag_6']?.()
  __napiInstance.exports['__napi_register__Keyword_struct_7']?.()
  __napiInstance.exports['__napi_register__extract_8']?.()
  __napiInstance.exports['__napi_register__load_tfidf_dict_9']?.()
}
module.exports.cut = __napiModule.exports.cut
module.exports.cutAll = __napiModule.exports.cutAll
module.exports.cutForSearch = __napiModule.exports.cutForSearch
module.exports.extract = __napiModule.exports.extract
module.exports.load = __napiModule.exports.load
module.exports.loadDict = __napiModule.exports.loadDict
module.exports.loadTFIDFDict = __napiModule.exports.loadTFIDFDict
module.exports.tag = __napiModule.exports.tag
