#![feature(generic_const_exprs)]
use ethers::{
    prelude::*,
    providers::{Provider, Http},
    core::types::{Address, Bytes, TransactionRequest, transaction::eip2718::TypedTransaction},
    utils::hex,
};
use std::error::Error;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_solidity_verifier::SolidityGenerator;
use summa_solvency::circuits::{
    univariate_grand_sum::{NoRangeCheckConfig, UnivariateGrandSum, UnivariateGrandSumConfig},
    utils::generate_setup_artifacts,
};

async fn get_verifying_key_code(client: &Provider<Http>, contract_address: Address) -> Result<Bytes, Box<dyn Error>> {
    // Function selector for verifyingKey
    let selector = hex::decode("7950c5f8")?;

    // Construct the call data (just the selector in this case)
    let call_data = Bytes::from(selector);

    // Create a TransactionRequest
    let tx = TransactionRequest {
        to: Some(contract_address.into()),
        data: Some(call_data),
        ..Default::default()
    };

    // Convert TransactionRequest to TypedTransaction
    let typed_tx: TypedTransaction = tx.into();

    // Make the call
    let result = client.call(&typed_tx, None).await?;

    // Parse the result to get the verifying key address
    let verifying_key_address = Address::from_slice(&result[12..32]);

    // Get the code at the verifying key address
    let verifying_key_code = client.get_code(verifying_key_address, None).await?;

    Ok(verifying_key_code)
}

async fn run(summa_address: Address, api_endpoint: &str) -> Result<String, Box<dyn Error>> {
    let provider = Provider::<Http>::try_from(api_endpoint)?;
    let verifying_key_code = get_verifying_key_code(&provider, summa_address).await?;
    Ok(hex::encode(verifying_key_code))
}

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;

async fn generate_vk() -> Result<String, Box<dyn Error>> {
    let circuit = UnivariateGrandSum::<
        N_USERS,
        N_CURRENCIES,
        UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>,
    >::init_empty();

    let (params, pk, _) =
        generate_setup_artifacts(K, Some("../backend/ptau/hermez-raw-17"), &circuit)?;

    let generator = SolidityGenerator::new(
        &params,
        pk.get_vk(),
        halo2_solidity_verifier::BatchOpenScheme::Bdfg21,
        1,
    );
    let (_, vk) = generator.render_separately()?;

    let mut vk_output = String::new();
    for line in vk.lines() {
        if line.contains("mstore(") {
            if let Some(start) = line.find(",") {
                let hex_value = &line[start + 4..start + 68];
                vk_output.push_str(hex_value);
            }
        }
    }
    // println!("{}", vk_output);
    Ok(vk_output)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err("Usage: vk_parsed <SUMMA_ADDRESS> <API_ENDPOINT>".into());
    }

    let summa_address = args[1].parse::<Address>()?;
    let api_endpoint = &args[2];

    // Run the original functionality
    let parsed_key_code = run(summa_address, api_endpoint).await?;

    // Generate VK values
    let generated_vk = generate_vk().await?;

    // Compare the results
    if parsed_key_code == generated_vk {
        println!("The parsed VK matches the generated VK values.");
    } else {
        println!("The parsed VK does not match the generated VK values.");
    }

    Ok(())
}