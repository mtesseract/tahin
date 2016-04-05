-- Tahin
-- Copyright (C) 2015, 2016 Moritz Schulte <mtesseract@silverratio.net>

{-# LANGUAGE OverloadedStrings          #-}

module Main where

import qualified System.Console.Haskeline as HL
import qualified Data.Map                 as M
import           System.Exit
import           Options.Applicative
import           Control.Exception
import           Control.Monad.Identity (runIdentity)
import           Control.Monad.Reader
import           Data.Maybe
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
import qualified Data.Text                as T
import qualified Data.Text.IO             as TIO
import           Data.Text (Text)

-- | The type of a hash function; a hash function maps a ByteString to
-- a ByteString.
type HashFunction = BS.ByteString -> BS.ByteString

-- | A Hash object contains a name and a HashFunction.
data Hash =
  Hash { hashString   :: String        -- ^ Name of this hashing algorithm
       , hashFunction :: HashFunction  -- ^ The hash function
       }

-- | A TahinEnv contains the environment we pass down using the
-- ReaderT monad transformer.
data TahinEnv = TahinEnv { tahinEnvOptions :: TahinOptions }

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

-- | Supported hashes.
hashes :: [Hash]
hashes = [ Hash "SHA1"      SHA1.hash
         , Hash "SHA224"    SHA224.hash
         , Hash "SHA256"    SHA256.hash
         , Hash "SHA384"    SHA384.hash
         , Hash "SHA512"    SHA512.hash
         , Hash "TIGER"     Tiger.hash
         , Hash "WHIRLPOOL" Whirlpool.hash ]

-- | Supported hashes as a map, mapping their names to the respective
-- Hash values.
hashesMap :: M.Map String Hash
hashesMap = M.fromList $ map (\ hash@(Hash name _) -> (name, hash)) hashes

-- | The default hash function used by Nokee.
defaultHash :: String
defaultHash = "SHA256"

-- | The default maximum length of the base64 encoded bytestring.
defaultLength :: Int
defaultLength = 20

-- | Master password prompt.
defaultPromptMaster1 :: Text
defaultPromptMaster1 = "Master Password"

-- | Master password prompt (retype).
defaultPromptMaster2 :: Text
defaultPromptMaster2 = "Master Password (retype)"

-- | Identifier prompt.
defaultPromptIdentifier :: Text
defaultPromptIdentifier = "Identifier"

-- | Displays a prompt and tries to read a password from the
-- terminal. Returns Maybe a String wrapped in IO.
readPassword :: Text -> ReaderT TahinEnv IO (Maybe Text)
readPassword prompt = liftIO $
  HL.runInputT HL.defaultSettings $
    fmap T.pack <$> HL.getPassword (Just '*') (T.unpack (T.concat [prompt, ": "]))

-- | Displays a prompt and tries to read a password from the
-- terminal. On failure, throw an exception.
readPassword' :: Text -> String -> ReaderT TahinEnv IO Text
readPassword' prompt errMsg = do
  maybePassword <- readPassword prompt
  case maybePassword of
    Just password -> return password
    Nothing       -> throw (TahinExceptionString errMsg)

-- | Command Dispatcher.
commandDispatcher :: ReaderT TahinEnv IO ()
commandDispatcher = do
  cmds <- mapReaderT (return . runIdentity) extractCommands
  let cmd = case cmds of
        []  -> runTahin -- Default command is run Tahin.
        [c] -> c        -- If exactly one command is given, execute it.
        _   ->
          -- Fail, if multiple commands are given.
          throw (TahinExceptionString "Multiple commands specified")
  cmd

  where -- | This function usees commandSpec to compute the list of
        -- specified commands.
        extractCommands = do
          maybeCmds <- forM commandSpec
            (\ (cmdTest, cmdFunc) -> do
                testRes <- cmdTest
                if testRes
                   then return $ Just cmdFunc
                   else return Nothing)
          return $ catMaybes maybeCmds

        -- | This defines the commands supported (besides the default
        -- command) along with suitable test functions, which check if
        -- the respective command is given.
        commandSpec =
          [ (optsVersion    . tahinEnvOptions <$> ask, printVersion)
          , (optsListHashes . tahinEnvOptions <$> ask, listHashes) ]
        

-- | This function is just a wrapper around the function 'runTahin', adding
-- exception handling. It gets called after arguments have been
-- parsed.
main' :: TahinOptions -> IO ()
main' opts = do
  let tahinEnv = TahinEnv { tahinEnvOptions = opts }
  catch (runReaderT commandDispatcher tahinEnv)
        (\ e -> case (e :: TahinException) of
                  TahinExceptionString s -> do putStrLn $ "Error: " ++ s
                                               exitFailure
                  TahinExceptionNone     -> return ())

-- | Print version information to stdout.
printVersion :: ReaderT TahinEnv IO ()
printVersion = liftIO $ putStrLn $ programName ++ " " ++ programVersion

-- | Print supported hashes to stdout.
listHashes :: ReaderT TahinEnv IO ()
listHashes = do
  let hashNames = map fst (M.toList hashesMap)
  mapM_ (liftIO . putStrLn) hashNames

-- | Try to lookup a hashing function by its name.
lookupHash :: String -> Maybe Hash
lookupHash hashName = M.lookup hashName' hashesMap
  where hashName'   = toUpperCase hashName
        toUpperCase = map toUpper

-- | May throw exceptions of type TahinException
lookupHash' :: String -> Hash
lookupHash' hashName =
  let maybeHash = lookupHash hashName
  in fromMaybe (throw (TahinExceptionString ("Unknown hash: " ++ hashName)))
       maybeHash

-- | This function implements the main program logic. May throw
-- TahinExceptions, they will be handled in the caller.
runTahin :: ReaderT TahinEnv IO ()
runTahin = do
  opts <- tahinEnvOptions <$> ask
  let len      = optsLength opts
      hashName = map Data.Char.toUpper (optsHash opts)
      hash     = lookupHash' hashName

  -- Force evaluation in order to trigger hash-not-found exception now
  -- in case the specified hash could not be found:
  _ <- liftIO $ evaluate hash

  infoMessage $ "Using hash function " ++ hashName
  infoMessage $ "Length is at most " ++ show len

  passwdMaster     <- retrieveMasterPassword
  passwdIdentifier <- readPassword' defaultPromptIdentifier errMsgRetrieveIdentifier

  let tahinPasswd  = tahin (hashFunction hash) len passwdMaster passwdIdentifier
  liftIO $ TIO.putStrLn tahinPasswd

  where errMsgRetrieveMasterPasswd = "Failed to retrieve master password"
        errMsgRetrieveIdentifier   = "Failed to retrieve password identifier"

        verifyPasswords pw1 pw2 =
          if pw1 == pw2
             then return pw1
             else throw (TahinExceptionString "Password mismatch")

        retrieveMasterPassword = do
          twice <- optsTwice . tahinEnvOptions <$> ask
          if twice
             then retrieveMasterPasswordTwice
             else retrieveMasterPasswordOnce

        retrieveMasterPasswordOnce =
          readPassword' defaultPromptMaster1 errMsgRetrieveMasterPasswd

        retrieveMasterPasswordTwice = do
          master1 <- readPassword' defaultPromptMaster1 errMsgRetrieveMasterPasswd
          master2 <- readPassword' defaultPromptMaster2 errMsgRetrieveMasterPasswd
          verifyPasswords master1 master2

-- | Type holding the information about parsed arguments.
data TahinOptions = TahinOptions
  { optsVersion    :: Bool
  , optsListHashes :: Bool
  , optsVerbose    :: Bool
  , optsHash       :: String
  , optsLength     :: Int
  , optsTwice      :: Bool
  }

-- | Print an informational if verbose is activated.
infoMessage :: String -> ReaderT TahinEnv IO ()
infoMessage msg = do
  opts <- tahinEnvOptions <$> ask
  when (optsVerbose opts) $
    liftIO $ putStrLn ("[ " ++ msg ++ " ]")

-- | The argument parser.
tahinOptions :: Parser TahinOptions
tahinOptions = TahinOptions
     <$> switch
         (long "version"
          <> help "Display version information")
     <*> switch
         (long "list-hashes"
          <> help "List supported hashes")
     <*> switch
         (long "verbose"
          <> help "Enable verbose mode")
     <*> strOption
         (long "hash"
          <> short 'h'
          <> value defaultHash
          <> metavar "HASH"
          <> help "Specify which hash to use")
     <*> option auto
         (long "length"
          <> value defaultLength
          <> short 'l'
          <> metavar "LENGTH"
          <> help "Specify maximum length of the password to generate")
     <*> switch
         (long "twice"
          <> short 't'
          <> help "Ask twice for the master password (e.g. for setting new passwords)")

-- | Main entry point.
main :: IO ()
main = execParser opts >>= main'
  where opts = info (helper <*> tahinOptions)
                 (fullDesc
                  <> progDesc programDescription
                  <> header (programName ++ " - " ++ programDescriptionShort))
