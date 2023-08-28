{-# LANGUAGE TypeApplications #-}

module Sel.Scrypt where

import LibSodium.Bindings.Scrypt
import LibSodium.Bindings.Random
import Sel.Internal
import Foreign (ForeignPtr, mallocForeignPtrBytes, withForeignPtr, void)
import Foreign.C (CChar, CULLong, CSize)
import GHC.IO.Unsafe (unsafeDupablePerformIO)
import Data.ByteString as BS (StrictByteString)
import Data.ByteString.Unsafe as BSU (unsafeUseAsCStringLen)
import LibSodium.Bindings.PasswordHashing (cryptoPWHash)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)

newtype ScryptPasswordHash = ScryptPasswordHash (ForeignPtr CChar)

instance Eq ScryptPasswordHash where
  (ScryptPasswordHash sph1) == (ScryptPasswordHash sph2) =
    unsafeDupablePerformIO $
      foreignPtrEq sph1 sph2 cryptoPWHashScryptSalsa2018SHA256StrBytes

instance Ord ScryptPasswordHash where
  (ScryptPasswordHash sph1) `compare` (ScryptPasswordHash sph2) =
    unsafeDupablePerformIO $
      foreignPtrOrd sph1 sph2 cryptoPWHashScryptSalsa2018SHA256StrBytes

instance Show ScryptPasswordHash where
  show (ScryptPasswordHash fptr) = foreignPtrShow fptr cryptoPWHashScryptSalsa2018SHA256StrBytes

hashByteStringScrypt :: StrictByteString -> IO ScryptPasswordHash
hashByteStringScrypt bytestring =
  BSU.unsafeUseAsCStringLen bytestring $ \(cString, cStringLen) -> do
    hashForeignPtr <- Foreign.mallocForeignPtrBytes (fromIntegral cryptoPWHashScryptSalsa2018SHA256StrBytes)
    Foreign.withForeignPtr hashForeignPtr $ \passwordHashPtr ->
      void $
        cryptoPWHashScryptSalsa2018SHA256Str
          passwordHashPtr
          cString
          (fromIntegral @Int @CULLong cStringLen)
          (fromIntegral @CSize @CULLong cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive)
          cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive
    pure $ ScryptPasswordHash hashForeignPtr

hashTextScrypt :: Text -> IO ScryptPasswordHash
hashTextScrypt text = hashByteStringScrypt (encodeUtf8 text)