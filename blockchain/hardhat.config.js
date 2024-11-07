require("@nomiclabs/hardhat-waffle");

module.exports = {
  solidity: "0.8.0",
  networks: {
    hardhat: {
      forking: {
        url: "https://eth-mainnet.alchemyapi.io/v2/your-alchemy-api-key", // Replace with your Alchemy API key
        blockNumber: 12843000 // Replace with the block number you want to fork from
      }
    }
  }
};