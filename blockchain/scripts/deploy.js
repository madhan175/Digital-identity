const hre = require("hardhat");

async function main() {
  const BlockAuthDID = await hre.ethers.getContractFactory("BlockAuthDID");
  const blockAuthDID = await BlockAuthDID.deploy();

  await blockAuthDID.deployed();

  console.log("BlockAuthDID deployed to:", blockAuthDID.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
