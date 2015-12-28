-- Tahin
-- Copyright (C) 2015 Moritz Schulte <mtesseract@silverratio.net>

module Main where

import qualified Crypto.Hash.SHA256       as SHA256
import qualified Data.ByteString          as BS
-- import qualified Data.ByteString.Base16   as B16
import qualified Data.ByteString.Base64   as B64
import qualified Data.ByteString.Char8    as BS8
import           System.Console.Haskeline
import           System.Exit

defaultHash :: BS.ByteString -> BS.ByteString
defaultHash = SHA256.hash

defaultEncoder :: BS.ByteString -> BS.ByteString
defaultEncoder = B64.encode

hashBase64 :: String -> String
hashBase64 = BS8.unpack . defaultEncoder . defaultHash . BS8.pack
-- hashBase16 = BS8.unpack . defaultEncoder . defaultHash . BS8.pack

passwordLength :: Int
passwordLength = 20

defaultPromptMaster :: String
defaultPromptMaster = "Master Password"

defaultPromptIdentifier :: String
defaultPromptIdentifier = "Identifier"

readPassword :: String -> IO (Maybe String)
readPassword prompt = do
  runInputT defaultSettings $
    getPassword (Just '*') (prompt ++ ": ")

tahin :: String -> String
tahin = (take passwordLength) . hashBase64

main :: IO ()
main = do
  maybePasswdMaster     <- readPassword defaultPromptMaster
  maybePasswdIdentifier <- readPassword defaultPromptIdentifier
  let passwd = (++) <$> maybePasswdMaster <*> maybePasswdIdentifier
  case passwd of
    Just p  -> putStrLn $ tahin p
    Nothing -> exitWith (ExitFailure 1)
