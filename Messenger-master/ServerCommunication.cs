//author: Griffin Danner-Doran
//This file contains the ServerCommunication class, which is used to get/send keys and messages to the remote server
//using HTTP requests.


using System.Text;
using Newtonsoft.Json;

namespace Messenger;

/// <summary>
/// This class contains 2 methods using HTTP GET requests for retrieving keys and messages, as well as 2 methods using
/// PUT requests to send keys and messages to the remote server.
/// </summary>
public class ServerCommunication
{
    //This is the HTTPClient used across all methods
    static readonly HttpClient client = new();

    /// <summary>
    /// This method uses a GET request to retrieve the key corresponding to the given email from the remote server and
    /// writes it to a key file corresponding the email.
    /// </summary>
    /// <param name="email">The email whose key is retrieved, also used as the name for the new key file.</param>
    /// <returns>The string "Key Received" in a success case, otherwise an HTTP error message.</returns>
    public async Task<string> GetKeyFromServer(string email)
    {
        try
        {
            var response = await client.GetAsync("{server}/Key/" + email);
            response.EnsureSuccessStatusCode();
            var keyJson = await response.Content.ReadAsStringAsync();
            var f = new FileInfo(email + ".key");
            var fileWriter = new StreamWriter(f.Create());
            await fileWriter.WriteLineAsync(keyJson);
            fileWriter.Close();
            return "Key received";
        }
        catch (HttpRequestException e)
        {
            return "HTTP exception occured with code " + e.StatusCode + " and error message " + e.Message;
        }
    }

    /// <summary>
    /// This method uses a PUT request to send a public key associated with the given email to the remote server. This
    /// email is also written to the private key file so that messages sent to the email can be retrieved and decrypted.
    /// </summary>
    /// <param name="email">The email to associate with our public key.</param>
    /// <returns>The string "Key Saved" in a success case, otherwise an HTTP error message.</returns>
    public async Task<string> SendKeyToServer(string email)
    {
        try
        {
            //TODO ask if there is any difference between File.ReadAllText and fileinfo.readtoend
            var publicFile = new FileInfo("public.key");
            var publicFileReader = new StreamReader(publicFile.OpenRead());
            var publicKeyJson = await publicFileReader.ReadToEndAsync();
            var publicKey = JsonConvert.DeserializeObject<PublicKey>(publicKeyJson);
            publicFileReader.Close();
            publicKey!.email = email;
            var content = new StringContent(JsonConvert.SerializeObject(publicKey), Encoding.UTF8, "application/json");
            var response = await client.PutAsync("{server}/Key/" + email, content);
            response.EnsureSuccessStatusCode();

            //we have now successfully sent key to server, store the email
            var privateFile = new FileInfo("private.key");
            var privateFileReader = new StreamReader(privateFile.OpenRead());
            var privateKeyJson = await privateFileReader.ReadToEndAsync();
            privateFileReader.Close();
            var privateKey = JsonConvert.DeserializeObject<PrivateKey>(privateKeyJson);
            privateKey!.email.Add(email);
            privateKeyJson = JsonConvert.SerializeObject(privateKey);
            var fileWriter = new StreamWriter(privateFile.Create());
            await fileWriter.WriteLineAsync(privateKeyJson);
            fileWriter.Close();
            return "Key saved";
        }
        catch (HttpRequestException e)
        {
            return "HTTP exception occured with code " + e.StatusCode + " and error message " + e.Message;
        }
    }


    /// <summary>
    /// This method sends a message to the target email RSA encrypted with their key using a PUT request.
    /// </summary>
    /// <param name="email">The email to send the message to and whose public key is used for encryption.</param>
    /// <param name="plaintext">The message to be encrypted and sent.</param>
    /// <returns>The string "Message Written" in a success case, otherwise an HTTP error message.</returns>
    public async Task<string> SendMsgToServer(string email, string plaintext)
    {
        try
        {
            var r = new RSA();
            var ciphertext = r.EncryptMessage(plaintext, email + ".key");
            var messageToSend = new Message
            {
                email = email,
                content = ciphertext
            };

            var content = new StringContent(JsonConvert.SerializeObject(messageToSend), Encoding.UTF8,
                "application/json");
            var response = await client.PutAsync("{server}/Message/" + email, content);
            response.EnsureSuccessStatusCode();
            return "Message written";
        }
        catch (HttpRequestException e)
        {
            return "HTTP exception occured with code " + e.StatusCode + " and error message " + e.Message;
        }
    }

    /// <summary>
    /// This method retrieves a message for the given email with a GET request and RSA decrypts them with the private key.
    /// </summary>
    /// <param name="email">The email alias to retrieve messages as.</param>
    /// <returns>The decrypted plaintext string in a success case, otherwise an HTTP error message.</returns>
    public async Task<string> GetMsgFromServer(string email)
    {
        try
        {
            var r = new RSA();
            var response = await client.GetAsync("{server}/Message/" + email);
            response.EnsureSuccessStatusCode();
            var messageJson = await response.Content.ReadAsStringAsync();
            var message = JsonConvert.DeserializeObject<Message>(messageJson);
            var plaintext = r.DecryptMessage(message!.content);
            return plaintext;
        }
        catch (HttpRequestException e)
        {
            return "HTTP exception occured with code " + e.StatusCode + " and error message " + e.Message;
        }
    }
}