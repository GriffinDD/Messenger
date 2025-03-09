//author: Griffin Danner-Doran
//This file contains the classes used to store messages and keys, as well as convert to and from JSON format.

namespace Messenger
{
    /// <summary>
    /// This class represents a public key object.
    /// </summary>
    internal class PublicKey
    {
        public required string email { get; set; }
        public required string key { get; set; }
    }

    /// <summary>
    /// This class represents a private key object.
    /// </summary>
    internal class PrivateKey
    {
        public required List<string> email { get; set; }
        public required string key { get; set; }
    }

    /// <summary>
    /// This class represents a message object, used for both sending and receiving messages.
    /// </summary>
    internal class Message
    {
        public required string email { get; set; }
        public required string content { get; set; }
    }
}