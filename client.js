const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto"); // Untuk generate pasangan kunci RSA

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = ""; // Username asli pengguna
let username = ""; // Username aktif (bisa berubah untuk impersonasi)
const users = new Map(); // Menyimpan pasangan username dan public key

// Generate pasangan kunci RSA (2048-bit untuk keamanan)
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

socket.on("connect", () => {
  console.log("Connected to the server");

  // Menerima daftar user dan public key dari server
  socket.on("init", (keys) => {
    keys.forEach(([user, key]) => users.set(user, key));
    console.log(`Currently ${users.size} users in the chat`);

    rl.question("Enter your username: ", (input) => {
      username = input;
      registeredUsername = input;
      console.log(`Welcome, ${username}!`);

      // Kirim public key pengguna ke server
      socket.emit("registerPublicKey", {
        username,
        publicKey: publicKey.export({ type: "pkcs1", format: "pem" }),
      });
      rl.prompt();

      // Menangani input dari pengguna
      rl.on("line", (message) => {
        if (message.trim()) {
          // Command untuk impersonasi pengguna lain
          if ((match = message.match(/^!impersonate (\w+)$/))) {
            username = match[1];
            console.log(`Now impersonating as ${username}`);
          }
          // Command untuk kembali ke username asli
          else if (message.match(/^!exit$/)) {
            username = registeredUsername;
            console.log(`Now you are back as ${username}`);
          }
          // Mengirim pesan
          else {
            const sign = crypto.createSign("sha256");
            sign.update(message);
            sign.end();
            const signature = sign.sign(privateKey, "hex");

            socket.emit("message", { username, message, signature });
          }
        }
        rl.prompt();
      });
    });
  });
});

// Menangani pengguna baru yang bergabung
socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} has joined the chat.`);
  rl.prompt();
});

// Menangani pesan yang diterima dari server
socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage, signature } = data;

  if (senderUsername !== username) {
    const senderPublicKey = users.get(senderUsername);

    if (senderPublicKey && signature) {
      const verify = crypto.createVerify("sha256");
      verify.update(senderMessage);
      verify.end();
      const isVerified = verify.verify(senderPublicKey, signature, "hex");

      if (isVerified) {
        console.log(`${senderUsername}: ${senderMessage}`);
      } else {
        console.log(`${senderUsername}: ${senderMessage}`);
        console.log("Warning: This message might be tampered with.");
      }
    } else if (!signature) {
      console.log(`Warning: ${senderUsername} sent a message without a signature.`);
    } else {
      console.log(`Warning: No public key found for ${senderUsername}.`);
    }
  }
  rl.prompt();
});

// Menangani disconnect dari server
socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

// Menangani SIGINT (Ctrl+C)
rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
