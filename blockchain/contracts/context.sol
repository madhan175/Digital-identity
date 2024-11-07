
const { ethers } = require('ethers');//+
const Context = require('./generated/Context'); // Replace with the actual path to your generated JavaScript wrapper//+

async function exampleUsage() {
  const provider = new ethers.providers.JsonRpcProvider('https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID');
  const signer = provider.getSigner();

  const context = new Context(provider, signer);

  const sender = await context._msgSender();
  console.log('Sender:', sender);

  const data = await context._msgData();
  console.log('Data:', data);
}

exampleUsage();
