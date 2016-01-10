-- Tahin
-- Copyright (C) 2015, 2016 Moritz Schulte <mtesseract@silverratio.net>

module Tahin ( TahinException(..), tahin) where

import qualified Data.ByteString          as BS
import qualified Data.ByteString.Base64   as B64
import qualified Data.ByteString.Char8    as BS8
import           Control.Exception
import           Data.Typeable

-----------------------------
-- Define Tahin exceptions --
-----------------------------

-- | Exception type used in Tahin.
data TahinException =
  TahinExceptionNone            -- ^ Exception value representing no
                                -- exception
  | TahinExceptionString String -- ^ Exception value holding an error
                                -- message
  deriving (Show, Typeable)

-- | A 'NokeeException' is an 'Exception'.
instance Exception TahinException


-------------------------
-- Main tahin function --
-------------------------

-- | Given a hash function and a maximum length, return a function
-- transforming a master password together with a identifier into a
-- new password.
tahin :: (BS.ByteString -> BS.ByteString) -> Int -> (String -> String -> String)
tahin hash len pwMaster pwIdentifier =
  let hashInput = pwMaster ++ " " ++ pwIdentifier
  in (take len . BS8.unpack . B64.encode . hash . BS8.pack) hashInput
