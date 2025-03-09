//author: Griffin Danner-Doran
//This file contains the Messenger class, which is used to create RSA key pairs and send them to a remote server, as
//well as send and receive encrypted messages from other clients.

using Newtonsoft.Json;

namespace Messenger
{
    /// <summary>
    /// This class parses the user arguments and makes sure they are valid, then passes them to an instance of the RSA
    /// or ServerCommunication classes to generate keys or communicate with the server respectively. It also handles
    /// displaying messages in both error and success cases. 
    /// </summary>
    public class Messenger
    {
        /// <summary>
        /// This method checks the user arguments and returns error messages if any formatting issues occur. If not, the
        /// arguments passed to an RSA instance in the case of key generation and a ServerCommunication instance for any
        /// HTTP communication with the remote server. Formatting checks are done before passing arguments to the instances
        /// and the results of the call, error or success, are displayed.
        /// </summary>
        /// <param name="args">
        /// args[0] the option to run with, can be keyGen, sendKey, getKey, sendMsg, getMsg.
        /// args[1] and args[2] vary based on the option chosen, but args[2] is only used with option sendMsg.
        /// </param>
        public static void Main(string[] args)
        {
            //instantiate the ServerCommunication instance used by all options except keyGen
            var serverConnection = new ServerCommunication();
            try
            {
                Task<string> messageResponse;
                if (args.Length == 3)
                {
                    if (args[0].Equals("sendMsg"))
                    {
                        //make sure we have a public key for the target email before sending a message
                        if (File.Exists(args[1] + ".key"))
                        {
                            var storedKey = File.ReadAllText(args[1] + ".key");
                            if (!storedKey.Trim().Equals(""))
                            {
                                messageResponse = Task.Run(() => serverConnection.SendMsgToServer(args[1], args[2]));
                                messageResponse.Wait();
                                //prints out the result, either "Message written" or an HTTP error if one occurred
                                Console.WriteLine(messageResponse.Result);
                            }
                            else
                            {
                                //if we grab an email's key and it is empty, they have not sent one to the server
                                Console.WriteLine("Email is missing a stored key");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Key does not exist for " + args[1]);
                        }
                    }
                    else
                    {
                        //only sendMsg supports 3 args, so if it is not sendMsg, then it is an incorrect command
                        throw new Exception();
                    }
                }
                else if (args.Length == 2) //if not sendMsg, then only 2 arguments
                {
                    switch (args[0])
                    {
                        case "keyGen":
                            int keysize;
                            //make sure we have a number as the key size
                            try
                            {
                                keysize = Int32.Parse(args[1]);
                            }
                            catch (Exception)
                            {
                                Console.WriteLine("Usage: dotnet run keyGen <keySize>");
                                Console.WriteLine(
                                    "    - keySize - the number of bits for the RSA key, this must be a multiple" +
                                    " of 8.");
                                break;
                            }

                            //we are sure we have a number, but only run if it can be correctly converted to bytes
                            if (keysize % 8 == 0)
                            {
                                var keyManager = new RSA();
                                keyManager.GenerateKeys(keysize);
                            }
                            else
                            {
                                Console.WriteLine("Key size in bits must be a multiple 8");
                            }

                            break;
                        case "sendKey":
                            //make sure key pair has already been generated
                            if (File.Exists("public.key") && File.Exists("private.key"))
                            {
                                messageResponse = Task.Run(() => serverConnection.SendKeyToServer(args[1]));
                                messageResponse.Wait();
                                Console.WriteLine(messageResponse.Result);
                            }
                            else
                            {
                                Console.WriteLine("Local public/private key pair does not exist");
                            }

                            break;
                        case "getKey":
                            messageResponse = Task.Run(() => serverConnection.GetKeyFromServer(args[1]));
                            messageResponse.Wait();
                            //only print something for this command if we get an HTTP error
                            if (messageResponse.Result != "Key received")
                            {
                                Console.WriteLine(messageResponse.Result);
                            }

                            break;
                        case "getMsg":
                            //make sure the private.key file exists at all before we check it
                            if (!File.Exists("private.key"))
                            {
                                Console.WriteLine("No private key stored for " + args[1]);
                                break;
                            }
                            
                            var privateKeyJson = File.ReadAllText("private.key");
                            var privateKey = JsonConvert.DeserializeObject<PrivateKey>(privateKeyJson);
                            //make sure that we have a private key corresponding the email we are getting a message for
                            if (privateKey!.email.Contains(args[1]))
                            {
                                messageResponse = Task.Run(() => serverConnection.GetMsgFromServer(args[1]));
                                messageResponse.Wait();
                                Console.WriteLine(messageResponse.Result);
                            }
                            else
                            {
                                Console.WriteLine("No private key stored for " + args[1]);
                            }

                            break;
                        default:
                            //any argument other than these is an error, go to main usage message
                            throw new Exception();
                    }
                }
                else
                {
                    //again, any other number of args than 2 or 3 is invalid
                    throw new Exception();
                }
            }
            catch (Exception) //print full usage statement in case of general errors
            {
                Console.WriteLine("dotnet run <option> <other arguments>");
                Console.WriteLine("Options: ");
                Console.WriteLine(
                    "    keyGen <keySize> - generates an RSA key of the given size and stores it locally.");
                Console.WriteLine("        - keySize - the number of bits for the RSA key, this must be a multiple" +
                                  " of 8.");
                Console.WriteLine(
                    "    sendKey <email> - sends the locally stored public key paired with the given email to the server.");
                Console.WriteLine(
                    "        - email - the email for which to associate the local public on the remote server.");
                Console.WriteLine(
                    "    getKey <email> - retrieves and stores the public key associated with the provided email on the remote server.");
                Console.WriteLine("        - email - the email to retrieve the public key of.");
                Console.WriteLine(
                    "    sendMsg <email> <plaintext> - sends the message to the given email using their public key for encryption.");
                Console.WriteLine(
                    "        - email - the email to send the message, must have their public key already retrieved for use in encryption.");
                Console.WriteLine("        - plaintext - the unencoded message to be sent to the remote serve.r");
                Console.WriteLine(
                    "    getMsg <email> - retrieves the last message for the given email and decrypts with the local private key.");
                Console.WriteLine(
                    "        - email - the email to retrieve a message for, must be associated with the local private key.");
            }
        }
    }
}