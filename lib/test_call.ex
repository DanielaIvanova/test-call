defmodule TestCall do
  alias AeternityNode.Api.Transaction, as: TransactionApi
  alias AeppSDK.Client
  alias AeppSDK.Utils.Account, as: AccountUtils

  alias AeppSDK.Utils.{Encoding, Keys, Serialization, Transaction}
  alias AeppSDK.Utils.Hash
  alias AeternityNode.Api.Chain, as: ChainApi

  alias AeternityNode.Model.{
    ContractCreateTx,
    GenericSignedTx,
    ContractCallObject,
    TxInfoObject,
    Error,
    Tx,
    PostTxResponse
  }

  alias Tesla.Env

  @default_deposit 0
  @default_amount 0
  @default_gas 1_000_000
  @default_gas_price 1_000_000_000
  @init_function "init"
  @fate_ct_version 0x50003
  @aevm_ct_version 0x60001
  @await_attempts 75
  @await_attempt_interval 200

  def deploy do
    client = client()

    source_code = "contract Number =
      record state = { number : int }

      entrypoint init(x : int) =
        { number = x }

      entrypoint add_to_number(x : int) =
        state.number + x"
    init_args = ["42"]

    deploy(client, source_code, init_args)
  end

  def search_contract(hash) do
    client = client()
    AeppSDK.Contract.get(client, hash)
  end

  def get_tx_info_by_hash(hash) do
    client = client()
    TransactionApi.get_transaction_info_by_hash(client.connection, hash)
  end

  def client do
    public_key = "ak_jQGc3ECvnQYDZY3i97WSHPigL9tTaVEz1oLBW5J4F1JTKS1g7"

    secret_key =
      "24865931054474805885eec12497ee398bc39bc26917c190ed435e3cd1fa954e6046ef581eef749d492360b1542c7be997b5ddca0d2e510a4312b217998bfc74"

    network_id = "ae_uat"
    url = "https://sdk-testnet.aepps.com/v2"
    internal_url = "https://sdk-testnet.aepps.com/v2"

    AeppSDK.Client.new(%{public: public_key, secret: secret_key}, network_id, url, internal_url,
      gas_price: 1_000_000_000
    )
  end

  def deploy(
        %Client{
          keypair: %{public: public_key},
          connection: connection,
          network_id: network_id,
          gas_price: gas_price
        } = client,
        source_code,
        init_args,
        opts \\ []
      )
      when is_binary(source_code) and is_list(init_args) and is_list(opts) do
    public_key_binary = Keys.public_key_to_binary(public_key)
    {:ok, source_hash} = Hash.hash(source_code)
    user_fee = Keyword.get(opts, :fee, Transaction.dummy_fee())
    vm = Keyword.get(opts, :vm, :fate)

    with {:ok, ct_version} <- get_ct_version(opts),
         {:ok, nonce} <- AccountUtils.next_valid_nonce(client, public_key),
         {:ok,
          %{
            byte_code: byte_code,
            compiler_version: compiler_version,
            type_info: type_info,
            payable: payable
          }} <- compile(source_code, vm),
         {:ok, calldata} <-
           create_calldata(source_code, @init_function, init_args, vm),
         byte_code_fields = [
           source_hash,
           type_info,
           byte_code,
           compiler_version,
           payable
         ],
         serialized_wrapped_code <- Serialization.serialize(byte_code_fields, :sophia_byte_code),
         contract_create_tx <- %ContractCreateTx{
           owner_id: public_key,
           nonce: nonce,
           code: serialized_wrapped_code,
           abi_version: ct_version,
           deposit: Keyword.get(opts, :deposit, @default_deposit),
           amount: Keyword.get(opts, :amount, @default_amount),
           gas: Keyword.get(opts, :gas, @default_gas),
           gas_price: Keyword.get(opts, :gas_price, @default_gas_price),
           fee: user_fee,
           ttl: Keyword.get(opts, :ttl, Transaction.default_ttl()),
           call_data: calldata
         },
         {:ok, %{height: height}} <- ChainApi.get_current_key_block_height(connection),
         new_fee <-
           Transaction.calculate_n_times_fee(
             contract_create_tx,
             height,
             network_id,
             user_fee,
             gas_price,
             Transaction.default_fee_calculation_times()
           ) do
      response =
        post(
          client,
          %{contract_create_tx | fee: new_fee},
          Keyword.get(opts, :auth, :no_auth),
          :one_signature
        )

      contract_account = compute_contract_account(public_key_binary, nonce)
      IO.inspect(contract_account, label: "Contract_id: ")
      {:ok, response}
    else
      {:ok, %Error{reason: message}} ->
        {:error, message}

      {:error, _} = error ->
        error
    end
  end

  def get_ct_version(opts) do
    case Keyword.get(opts, :vm, :fate) do
      :fate ->
        {:ok, @fate_ct_version}

      :aevm ->
        {:ok, @aevm_ct_version}

      _ ->
        {:error, "Invalid VM"}
    end
  end

  def compile(source_code, vm \\ :fate) when is_binary(source_code) do
    charlist_source = String.to_charlist(source_code)

    try do
      :aeso_compiler.from_string(charlist_source, backend: vm)
    rescue
      e in ErlangError ->
        %ErlangError{original: {_, message}} = e

        {:error, message}
    end
  end

  def create_calldata(
        source_code,
        function_name,
        function_args,
        vm \\ :fate
      )
      when is_binary(source_code) and is_binary(function_name) and is_list(function_args) do
    charlist_source_code = String.to_charlist(source_code)
    charlist_function_name = String.to_charlist(function_name)

    charlist_function_args =
      Enum.map(function_args, fn arg ->
        String.to_charlist(arg)
      end)

    try do
      {:ok, calldata} =
        :aeso_compiler.create_calldata(
          charlist_source_code,
          charlist_function_name,
          charlist_function_args,
          backend: vm
        )

      {:ok, calldata}
    rescue
      e in ErlangError ->
        message =
          case e do
            %ErlangError{original: {_, message}} ->
              message

            %MatchError{term: {:error, message}} ->
              message
          end

        {:error, message}
    end
  end

  defp compute_contract_account(owner_address, nonce) do
    nonce_binary = :binary.encode_unsigned(nonce)
    {:ok, hash} = Hash.hash(<<owner_address::binary, nonce_binary::binary>>)

    Encoding.prefix_encode_base58c("ct", hash)
  end

  def encode_logs(logs, topic_types) do
    Enum.map(logs, fn log ->
      string_data = Encoding.prefix_decode_base64(log.data)

      log
      |> Map.from_struct()
      |> Map.replace!(:data, string_data)
      |> Map.update!(:topics, fn [event_name | rest_topics] = topics ->
        case topic_types do
          [] ->
            topics

          _ ->
            {encoded_topics, _} =
              Enum.reduce(rest_topics, {[], topic_types}, fn topic,
                                                             {encoded_topics,
                                                              [topic_type | rest_types]} ->
                {[encode_topic(topic_type, topic) | encoded_topics], rest_types}
              end)

            [event_name | Enum.reverse(encoded_topics)]
        end
      end)
    end)
  end

  defp encode_topic(:address, topic), do: encode_hash(topic, "ak")

  defp encode_topic(:contract, topic), do: encode_hash(topic, "ct")

  defp encode_topic(:oracle, topic), do: encode_hash(topic, "ok")

  defp encode_topic(:oracle_query, topic), do: encode_hash(topic, "oq")

  defp encode_topic(:int, topic), do: topic

  defp encode_topic(:bits, topic), do: topic

  defp encode_topic(:bytes, topic), do: topic

  defp encode_topic(:bool, topic) do
    case topic do
      1 ->
        true

      0 ->
        false
    end
  end

  defp encode_hash(hash, prefix) do
    binary_hash = :binary.encode_unsigned(hash)
    Encoding.prefix_encode_base58c(prefix, binary_hash)
  end

  def post(
        %Client{
          connection: connection,
          keypair: %{secret: secret_key},
          network_id: network_id
        },
        tx,
        :no_auth,
        signatures_list
      ) do
    type = Map.get(tx, :__struct__, :no_type)
    serialized_tx = Serialization.serialize(tx)

    signature =
      Keys.sign(
        serialized_tx,
        Keys.secret_key_to_binary(secret_key.()),
        network_id
      )

    signed_tx_fields =
      case signatures_list do
        :one_signature -> [[signature], serialized_tx]
        _ -> [signatures_list, serialized_tx]
      end

    serialized_signed_tx = Serialization.serialize(signed_tx_fields, :signed_tx)

    encoded_signed_tx = Encoding.prefix_encode_base64("tx", serialized_signed_tx)

    with {:ok, %PostTxResponse{tx_hash: tx_hash}} <-
           TransactionApi.post_transaction(connection, %Tx{
             tx: encoded_signed_tx
           }) do
      IO.inspect(tx_hash, label: "TX_HASH: ")
      await_mining(connection, tx_hash, ContractCreateTx)
    else
      {:ok, %Error{reason: message}} ->
        {:error, message}

      {:error, _} = error ->
        error
    end
  end

  def await_mining(connection, tx_hash, type) do
    await_mining(connection, tx_hash, @await_attempts, type)
  end

  @doc false
  def await_mining(_connection, _tx_hash, 0, _type),
    do:
      {:error,
       "Transaction wasn't mined after #{@await_attempts * @await_attempt_interval / 1_000} seconds"}

  @doc false
  def await_mining(connection, tx_hash, attempts, type) do
    Process.sleep(@await_attempt_interval)

    mining_status =
      case type do
        ContractCallTx ->
          TransactionApi.get_transaction_info_by_hash(connection, tx_hash)

        ContractCreateTx ->
          TransactionApi.get_transaction_info_by_hash(connection, tx_hash)

        _ ->
          TransactionApi.get_transaction_by_hash(connection, tx_hash)
      end

    case mining_status do
      {:ok, %GenericSignedTx{block_hash: "none", block_height: -1}} ->
        await_mining(connection, tx_hash, attempts - 1, type)

      {:ok, %GenericSignedTx{block_hash: block_hash, block_height: block_height, hash: tx_hash}} ->
        {:ok, %{block_hash: block_hash, block_height: block_height, tx_hash: tx_hash}}

      {:ok,
       %TxInfoObject{
         call_info: %ContractCallObject{
           log: log,
           return_value: return_value,
           return_type: return_type
         }
       }} ->
        {:ok, %GenericSignedTx{block_hash: block_hash, block_height: block_height, hash: tx_hash}} =
          TransactionApi.get_transaction_by_hash(connection, tx_hash)

        {:ok,
         %{
           block_hash: block_hash,
           block_height: block_height,
           tx_hash: tx_hash,
           return_value: return_value,
           return_type: return_type,
           log: log
         }}

      {:ok, %Error{}} ->
        await_mining(connection, tx_hash, attempts - 1, type)

      {:error, %Env{} = env} ->
        {:error, env}
    end
  end
end
