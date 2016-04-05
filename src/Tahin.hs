-- Tahin
-- Copyright (C) 2015-2016 Moritz Schulte <mtesseract@silverratio.net>

{-# LANGUAGE OverloadedStrings          #-}

module Tahin ( TahinException(..)
             , TahinPassword
             , TahinIdentifier
             , TahinTransformer
             , tahin ) where

import qualified Data.ByteString.Base64   as B64
import qualified Data.ByteString.Char8    as BS8
import           Control.Exception
import           Data.Typeable
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import           Data.Text (Text)

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

-- | A 'TahinPassword' is a type synonym for 'Text'; it is used for
-- passwords in the Tahin algorithm (this includes the master password
-- and the resulting password generated by Tahin).
type TahinPassword   = Text

-- | A TahinMasterPassword.
type TahinMasterPassword = Text

-- | A 'TahinIdentifier' is a type synonym for 'String'; it is used
-- for the '(service) identifier' in the Tahin algorithm.
type TahinIdentifier = Text

-- | A 'TahinTransformer' is a function mapping a
-- 'TahinMasterPassword' together with a 'TahinIdentifier' to a
-- 'TahinPassword'.
type TahinTransformer = TahinMasterPassword -> TahinIdentifier -> TahinPassword

-------------------------
-- Main tahin function --
-------------------------

-- | Given a hash function and a maximum length, return a
-- TahinTransformer.
tahin :: (BS8.ByteString -> BS8.ByteString) -> Int -> TahinTransformer
tahin hash len =
  curry (T.take len . TE.decodeUtf8 . B64.encode . hash . TE.encodeUtf8 . intercal)
  where intercal (pw, identifier) = T.intercalate " " [pw, identifier]
