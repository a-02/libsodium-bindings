{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Module: LibSodium.Bindings.Main
-- Description: Wrappers for initialization
-- Copyright: (C) Koz Ross 2022
-- License: BSD-3-Clause
-- Maintainer: koz.ross@retro-freedom.nz
-- Stability: Stable
-- Portability: GHC only
--
-- @libsodium@ requires initialization before use. We provide a binding to the
-- initialization function, as well as some high-level wrappers for applications
-- to use without needing to call an FFI wrapper.
--
-- = Note
--
-- If you are using @cryptography-libsodium@ as a dependency for a library, you
-- are probably not interested in this; it's designed for application authors who
-- need capabilities provided by @cryptography-libsodium@.
module LibSodium.Bindings.Main
  ( -- * High-level wrappers
    secureMain
  , secureMainWith

    -- * Low-level binding
  , sodiumInit
  )
where

import Data.Kind (Type)
import Foreign.C.Types (CInt (CInt))
import System.Exit (die)

-- | Initialize all security-related functionality, then perform the given
-- action. Abort with an error message if security-related functionality cannot
-- be initialized. This will also indicate failure to the shell, as with 'die'.
--
-- = Use
--
-- > main :: IO ()
-- > main = secureMain doTheThingIActuallyWant
--
-- @since 0.0.1.0
secureMain :: forall (a :: Type). IO a -> IO a
secureMain = secureMainWith (die "Could not initialize secure functionality, aborting.")

-- | Similar to 'secureMain', but allows responding to a failure of
-- initialization.
--
-- = Use
--
-- > main :: IO ()
-- > main = secureMainWith reportErrorWithLogging doTheThingIActuallyWant
--
-- @since 0.0.1.0
secureMainWith :: forall (a :: Type). IO a -> IO a -> IO a
secureMainWith badPath goodPath = do
  !res <- sodiumInit
  if res == (-1) then badPath else goodPath

-- | Initialize @libsodium@ for future use. This only needs to be called once,
-- before any use of any other functionality, but multiple calls to this
-- function are not harmful (just redundant).
--
-- = Corresponds to
--
-- [@sodium_init@](https://libsodium.gitbook.io/doc/usage)
--
-- @since 0.0.1.0
foreign import capi "sodium.h sodium_init"
  sodiumInit
    :: IO CInt
    -- ^ 0 if successful, -1 on failure, 1 on repeat calls
