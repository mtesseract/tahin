-- Tahin
-- Copyright (C) 2015-2016 Moritz Schulte <mtesseract@silverratio.net>

module Tahin ( TahinException(..)
             , TahinPassword
             , TahinIdentifier
             , TahinTransformer
             , tahin ) where

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

-- | A 'TahinPassword' is a type synonym for 'String'; it is used for
-- passwords in the Tahin algorithm (this includes the master password
-- and the resulting password generated by Tahin).
type TahinPassword   = String

-- | A 'TahinIdentifier' is a type synonym for 'String'; it is used
-- for the '(service) identifier' in the Tahin algorithm.
type TahinIdentifier = String

-- | A 'TahinTransformer' is a function mapping a 'TahinPassword' (the master password)
-- together with a 'TahinIdentifier' (the 'service identifier') to a
-- 'TahinPassword'.
type TahinTransformer = TahinPassword -> TahinIdentifier -> TahinPassword

-------------------------
-- Main tahin function --
-------------------------

-- | Given a hash function and a maximum length, return a
-- TahinTransformer.
tahin :: (BS.ByteString -> BS.ByteString) -> Int -> TahinTransformer
tahin hash len pwMaster pwIdentifier =
  let hashInput = pwMaster ++ " " ++ pwIdentifier
  in (take len . BS8.unpack . B64.encode . hash . BS8.pack) hashInput
