// @qshield/core — native addon loader
//
// This file is generated/managed by @napi-rs/cli.
// It loads the correct pre-built binary for the current platform/arch.

const { existsSync, readFileSync } = require('fs')
const path = require('path')

const { platform, arch } = process

let nativeBinding = null
let localFileExisted = false
let loadError = null

function isMusl() {
  // For Node 10+
  if (!process.report || typeof process.report.getReport !== 'function') {
    try {
      const lddPath = require('child_process').execSync('which ldd').toString().trim()
      return readFileSync(lddPath, 'utf8').includes('musl')
    } catch {
      return true
    }
  }
  const { glibcVersionRuntime } = process.report.getReport().header
  return !glibcVersionRuntime
}

switch (platform) {
  case 'android':
    switch (arch) {
      case 'arm64':
        localFileExisted = existsSync(path.join(__dirname, 'qshield.android-arm64.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./qshield.android-arm64.node')
          } else {
            nativeBinding = require('@qshield/core-android-arm64')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm':
        localFileExisted = existsSync(path.join(__dirname, 'qshield.android-arm-eabi.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./qshield.android-arm-eabi.node')
          } else {
            nativeBinding = require('@qshield/core-android-arm-eabi')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Android ${arch}`)
    }
    break
  case 'win32':
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(path.join(__dirname, 'qshield.win32-x64-msvc.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./qshield.win32-x64-msvc.node')
          } else {
            nativeBinding = require('@qshield/core-win32-x64-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'ia32':
        localFileExisted = existsSync(path.join(__dirname, 'qshield.win32-ia32-msvc.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./qshield.win32-ia32-msvc.node')
          } else {
            nativeBinding = require('@qshield/core-win32-ia32-msvc')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on Windows: ${arch}`)
    }
    break
  case 'darwin':
    switch (arch) {
      case 'x64':
        localFileExisted = existsSync(path.join(__dirname, 'qshield.darwin-x64.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./qshield.darwin-x64.node')
          } else {
            nativeBinding = require('@qshield/core-darwin-x64')
          }
        } catch (e) {
          loadError = e
        }
        break
      case 'arm64':
        localFileExisted = existsSync(path.join(__dirname, 'qshield.darwin-arm64.node'))
        try {
          if (localFileExisted) {
            nativeBinding = require('./qshield.darwin-arm64.node')
          } else {
            nativeBinding = require('@qshield/core-darwin-arm64')
          }
        } catch (e) {
          loadError = e
        }
        break
      default:
        throw new Error(`Unsupported architecture on macOS: ${arch}`)
    }
    break
  case 'linux':
    switch (arch) {
      case 'x64':
        if (isMusl()) {
          localFileExisted = existsSync(path.join(__dirname, 'qshield.linux-x64-musl.node'))
          try {
            if (localFileExisted) {
              nativeBinding = require('./qshield.linux-x64-musl.node')
            } else {
              nativeBinding = require('@qshield/core-linux-x64-musl')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(path.join(__dirname, 'qshield.linux-x64-gnu.node'))
          try {
            if (localFileExisted) {
              nativeBinding = require('./qshield.linux-x64-gnu.node')
            } else {
              nativeBinding = require('@qshield/core-linux-x64-gnu')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      case 'arm64':
        if (isMusl()) {
          localFileExisted = existsSync(path.join(__dirname, 'qshield.linux-arm64-musl.node'))
          try {
            if (localFileExisted) {
              nativeBinding = require('./qshield.linux-arm64-musl.node')
            } else {
              nativeBinding = require('@qshield/core-linux-arm64-musl')
            }
          } catch (e) {
            loadError = e
          }
        } else {
          localFileExisted = existsSync(path.join(__dirname, 'qshield.linux-arm64-gnu.node'))
          try {
            if (localFileExisted) {
              nativeBinding = require('./qshield.linux-arm64-gnu.node')
            } else {
              nativeBinding = require('@qshield/core-linux-arm64-gnu')
            }
          } catch (e) {
            loadError = e
          }
        }
        break
      default:
        throw new Error(`Unsupported architecture on Linux: ${arch}`)
    }
    break
  default:
    throw new Error(`Unsupported OS: ${platform}, architecture: ${arch}`)
}

if (!nativeBinding) {
  if (loadError) {
    throw loadError
  }
  throw new Error('Failed to load native binding')
}

const {
  KemLevel,
  DsaLevel,
  HybridMode,
  KemPublicKey,
  KemSecretKey,
  KemKeypair,
  DsaVerifyingKey,
  DsaKeypair,
  HybridPublicKey,
  HybridSecretKey,
  HybridKeypair,
  kemKeygen,
  kemEncapsulate,
  kemDecapsulate,
  dsaKeygen,
  dsaSign,
  dsaVerify,
  hybridKeygen,
  hybridEncapsulate,
  hybridDecapsulate,
  aes256gcmEncrypt,
  aes256gcmDecrypt,
  chacha20poly1305Encrypt,
  chacha20poly1305Decrypt,
  hkdfSha3256,
  randomBytes,
  generateNonce,
} = nativeBinding

module.exports = {
  KemLevel,
  DsaLevel,
  HybridMode,
  KemPublicKey,
  KemSecretKey,
  KemKeypair,
  DsaVerifyingKey,
  DsaKeypair,
  HybridPublicKey,
  HybridSecretKey,
  HybridKeypair,
  kemKeygen,
  kemEncapsulate,
  kemDecapsulate,
  dsaKeygen,
  dsaSign,
  dsaVerify,
  hybridKeygen,
  hybridEncapsulate,
  hybridDecapsulate,
  aes256gcmEncrypt,
  aes256gcmDecrypt,
  chacha20poly1305Encrypt,
  chacha20poly1305Decrypt,
  hkdfSha3256,
  randomBytes,
  generateNonce,
}
