-- Tahin
-- Copyright (C) 2015, 2016 Moritz Schulte <mtesseract@silverratio.net>

module Main where

import qualified System.Console.Haskeline as HL
import qualified Data.Map                 as M
import           System.Exit
import           Options.Applicative
import           Control.Exception
import           Data.Maybe
import           Control.Monad
import           Paths_Tahin
import           Data.Version
import           Data.Char
import           Tahin
import qualified Data.ByteString          as BS
import qualified Crypto.Hash.SHA1         as SHA1
import qualified Crypto.Hash.SHA224       as SHA224
import qualified Crypto.Hash.SHA256       as SHA256
import qualified Crypto.Hash.SHA384       as SHA384
import qualified Crypto.Hash.SHA512       as SHA512
import qualified Crypto.Hash.Tiger        as Tiger
import qualified Crypto.Hash.Whirlpool    as Whirlpool

type HashFunction = BS.ByteString -> BS.ByteString

-- | Supported hashes, mapping string identifiers to the respective
-- hash functions.
hashes :: M.Map String HashFunction
hashes = M.fromList [ ("SHA1"     , SHA1.hash     )
                    , ("SHA224"   , SHA224.hash   )
                    , ("SHA256"   , SHA256.hash   )
                    , ("SHA384"   , SHA384.hash   )
                    , ("SHA512"   , SHA512.hash   )
                    , ("TIGER"    , Tiger.hash    )
                    , ("WHIRLPOOL", Whirlpool.hash) ]

-- | The default hash function used by Nokee.
defaultHash :: String
defaultHash = "SHA256"

-- | The default maximum length of the base64 encoded bytestring.
defaultLength :: Int
defaultLength = 20

-- | Master password prompt.
defaultPromptMaster1 :: String
defaultPromptMaster1 = "Master Password"

-- | Master password prompt (retype).
defaultPromptMaster2 :: String
defaultPromptMaster2 = "Master Password (retype)"

-- | Identifier prompt.
defaultPromptIdentifier :: String
defaultPromptIdentifier = "Identifier"

-- | Displays a prompt and tries to read a password from the
-- terminal. Returns Maybe a String wrapped in IO.
readPassword :: String -> IO (Maybe String)
readPassword prompt =
  HL.runInputT HL.defaultSettings $
    HL.getPassword (Just '*') (prompt ++ ": ")

-- | Displays a prompt and tries to read a password from the
-- terminal. On failure, throw an exception.
readPassword' :: String -> String -> IO String
readPassword' prompt errMsg = do
  maybePassword <- readPassword prompt
  case maybePassword of
    Just password -> return password
    Nothing       -> throw (TahinExceptionString errMsg)

-- | The name of the program.
programName :: String
programName = "Tahin"

-- | The version of the program.
programVersion :: String
programVersion = showVersion version

-- | Short description of the program.
programDescriptionShort :: String
programDescriptionShort = "(Simple & Stupid) Password Generator"

-- | Short description of the program.
programDescription :: String
programDescription = "Tahin generates a password by concatenating a 'master password' \
                     \with an 'identifier', transforming this string with a hash \
                     \function and finally base64-encode the resulting binary string."

-- | This function is just a wrapper around the function 'runTahin', adding
-- exception handling. It gets called after arguments have been
-- parsed.
main' :: TahinOptions -> IO ()
main' opts =
  catch (runTahin opts)
        (\ e -> case (e :: TahinException) of
                  TahinExceptionString s -> do putStrLn $ "Error: " ++ s
                                               exitFailure
                  TahinExceptionNone     -> return ())

-- | Print version information to stdout.
printVersion :: IO ()
printVersion = putStrLn $ programName ++ " " ++ programVersion

-- | Try to lookup a hashing function by its name.
lookupHash :: String -> Maybe HashFunction
lookupHash hashName = M.lookup hashName' hashes
  where hashName' = toUpperCase hashName
        toUpperCase = map toUpper

-- | May throw exceptions of type TahinException
lookupHash' :: String -> IO HashFunction
lookupHash' hashName = do
  let maybeHashFun = lookupHash hashName
  return $! fromMaybe (throw (TahinExceptionString ("Unknown hash: " ++ hashName))) maybeHashFun

-- | This function implements the main program logic. May throw
-- TahinExceptions, they will be handled in the caller.
runTahin :: TahinOptions -> IO ()
runTahin opts = do
  -- Implement --version.
  when (optsVersion opts) $ do
    printVersion
    throw TahinExceptionNone

  let hashName = map Data.Char.toUpper (optsHash opts)
      len = optsLength opts

  hashFun <- lookupHash' hashName

  infoMessage opts $ "Using hash function " ++ hashName
  infoMessage opts $ "Length is at most " ++ show len

  passwdMaster1    <- readPassword' defaultPromptMaster1 errMsgRetrieveMasterPasswd
  passwdMaster2    <- readPassword' defaultPromptMaster2 errMsgRetrieveMasterPasswd
  passwdMaster     <- verifyPasswords passwdMaster1 passwdMaster2
  passwdIdentifier <- readPassword' defaultPromptIdentifier errMsgRetrieveIdentifier

  let tahinPasswd  = tahin hashFun len passwdMaster passwdIdentifier
  putStrLn tahinPasswd

  where errMsgRetrieveMasterPasswd = "Failed to retrieve master password"
        errMsgRetrieveIdentifier   = "Failed to retrieve password identifier"
        verifyPasswords pw1 pw2 =
          if pw1 == pw2
             then return pw1
             else throw (TahinExceptionString "Password mismatch")

-- | Type holding the information about parsed arguments.
data TahinOptions = TahinOptions
  { optsVersion :: Bool
  , optsVerbose :: Bool
  , optsHash    :: String
  , optsLength  :: Int }

infoMessage :: TahinOptions -> String -> IO ()
infoMessage opts msg =
  when (optsVerbose opts) $
    putStrLn $ "[ " ++ msg ++ " ]"

-- | The argument parser.
tahinOptions :: Parser TahinOptions
tahinOptions = TahinOptions
     <$> switch
         (long "version"
          <> help "Display version information")
     <*> switch
         (long "verbose"
          <> help "Enable verbose mode")
     <*> strOption
         (long "hash"
          <> value defaultHash
          <> metavar "HASH"
          <> help "Specify which hash to use")
     <*> option auto
         (long "length"
          <> value defaultLength
          <> short 'l'
          <> metavar "LENGTH"
          <> help "Specify maximum length of the password to generate")

-- | Main entry point.
main :: IO ()
main = execParser opts >>= main'
  where opts = info (helper <*> tahinOptions)
                 (fullDesc
                  <> progDesc programDescription
                  <> header (programName ++ " - " ++ programDescriptionShort))
