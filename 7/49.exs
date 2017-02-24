use Bitwise

defmodule CryptUtils do
  defmodule PaddingError do
    defexception message: "Invalid pkcs7 Padding"
  end

  ### ECB
  def aes_ecb_encrypt(key, data) do
    aes_ecb_encrypt_raw(key, pkcs7_pad(data, length(key)))
  end
  defp aes_ecb_encrypt_raw(key, data) do
    :crypto.block_encrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
  end

  def aes_ecb_decrypt(key, data) do
    aes_ecb_decrypt_raw(key, data) |> pkcs7_unpad(length(key))
  end
  defp aes_ecb_decrypt_raw(key, data) do
    :crypto.block_decrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
  end

  ### CBC
  def aes_cbc_encrypt(key, iv, data) do
    aes_cbc_encrypt_raw(key, iv, pkcs7_pad(data, length(key)))
  end
  defp aes_cbc_encrypt_raw(_key, _iv, []), do: []
  defp aes_cbc_encrypt_raw(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    encrypted = aes_ecb_encrypt_raw(key, fixed_xor(iv, block))
    encrypted ++ aes_cbc_encrypt_raw(key, encrypted, rest)
  end

  def aes_cbc_decrypt(key, iv, data) do
    aes_cbc_decrypt_raw(key, iv, data) |> pkcs7_unpad(length(key))
  end
  defp aes_cbc_decrypt_raw(_key, _iv, []), do: []
  defp aes_cbc_decrypt_raw(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    decrypted = fixed_xor(aes_ecb_decrypt_raw(key, block), iv)
    decrypted ++ aes_cbc_decrypt_raw(key, block, rest)
  end

  ### PKCS7 Padding
  def pkcs7_pad(binary, blocksize) when is_binary(binary) do
    pkcs7_pad(:binary.bin_to_list(binary), blocksize)
  end
  def pkcs7_pad(list, blocksize) do
    last_size = rem(length(list), blocksize)
    list ++ pkcs7_padding(blocksize - last_size)
  end

  def pkcs7_unpad(list, blocksize) do
    {most, last} = Enum.split(list, length(list) - blocksize)
    most ++ pkcs7_unpad_block(last)
  end
  defp pkcs7_unpad_block(list) do
    size = length(list)
    num = List.last(list)
    {unpadded, padding} = Enum.split(list, -num)
    if num > 0 and num < (size + 1) and padding == pkcs7_padding(num) do
      unpadded
    else
      list
    end
  end

  def pkcs7_padding(n), do: (for _ <- 1..n, do: n)

  ## Utils
  def to_64(list), do: list |> IO.iodata_to_binary |> Base.encode64
  def parse_64(string) do
    string |> Base.decode64!(ignore_whitespace: true) |> :binary.bin_to_list
  end

  def fixed_xor(l1, l2), do: Enum.zip(l1, l2) |> Enum.map(fn({b1, b2}) -> b1 ^^^ b2 end)

  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)
  def rand_lowercase(n), do: (for _ <- 1..n, do: 96 + :rand.uniform(26))

  def const_bytes(0, _), do: []
  def const_bytes(n, byte), do: (for _ <- 1..n, do: byte)

  def aes_cbc_mac(key, iv, data) do
    aes_cbc_encrypt(key, iv, data)
    |> Enum.chunk(length(key))
    |> List.last
  end
end

defmodule ServerA do
  @key [161, 232, 236, 7, 214, 38, 61, 116, 142, 72, 63, 67, 200, 233, 216, 122]

  def verify({msg, iv, mac}) do
    if mac == CryptUtils.aes_cbc_mac(@key, iv, msg) do
      args = URI.query_decoder(msg)  |> Enum.reduce(%{}, fn({k, v}, m) -> Map.put(m, k, v) end)
      "Sent #{args["amount"]} – From: #{args["from"]}  To: #{args["to"]}"
    end
  end
end

defmodule ClientA do
  @key [161, 232, 236, 7, 214, 38, 61, 116, 142, 72, 63, 67, 200, 233, 216, 122]

  @logged_in_id 1

  def create_message(to_id, amount) do
    msg = "from=#{@logged_in_id}&to=#{to_id}&amount=#{amount}"
    iv = CryptUtils.rand_bytes(length(@key))
    {msg, iv, CryptUtils.aes_cbc_mac(@key, iv, msg)}
  end
end

{msg, iv, mac} = ClientA.create_message(4, "1MSB")

IO.inspect ServerA.verify({msg, iv, mac})
IO.inspect ["Should not verify:", ServerA.verify({msg, iv, [hd(mac) - 1 | tl(mac)]})]

iv = List.replace_at(iv, 5, Enum.at(iv, 5) ^^^ (?1 ^^^ ?4))
     |> List.replace_at(10, Enum.at(iv, 10) ^^^ (?1 ^^^ ?4))

msg = :binary.bin_to_list(msg)
      |> List.replace_at(5, ?4)
      |> List.replace_at(10, ?1)
      |> IO.iodata_to_binary

# IO.inspect {msg, iv, mac}
IO.inspect ServerA.verify({msg, iv, mac})


defmodule ServerB do
  @key [161, 232, 236, 7, 214, 38, 61, 116, 142, 72, 63, 67, 200, 233, 216, 122]
  @iv CryptUtils.const_bytes(16, 0)

  def verify({msg, mac}) do
    if mac == CryptUtils.aes_cbc_mac(@key, @iv, msg) do
      args = URI.query_decoder(msg)  |> Enum.reduce(%{}, fn({k, v}, m) -> Map.put(m, k, v) end)
      txns = args["tx_list"]
             |> String.split(";")
             |> Enum.map(fn(tx) ->
               [to, amt] = String.split(tx, ":")
               "#{amt} To: #{to}"
             end)
             |> Enum.join(" | ")
      "Sending From #{args["from"]}: " <> txns
    end
  end
end

defmodule ClientB do
  @key [161, 232, 236, 7, 214, 38, 61, 116, 142, 72, 63, 67, 200, 233, 216, 122]
  @iv CryptUtils.const_bytes(16, 0)

  @logged_in_id 1

  def create_message(txns), do: create_message(txns, @logged_in_id)
  defp create_message(txns, from) do
    txn_msg = Enum.map(txns, fn({t, a}) -> "#{t}:#{a}" end) |> Enum.join(";")
    msg = "from=#{from}&tx_list=#{txn_msg}"
    {msg, CryptUtils.aes_cbc_mac(@key, @iv, msg)}
  end

  def capture do
    create_message([{7, 40}], 4)
  end
end

IO.puts "\n\t-------------------------------------------\n"

{msgV, macV} = ClientB.capture

IO.inspect ServerB.verify({msgV, macV})
IO.inspect ["Should not verify", ServerB.verify({msgV, [hd(macV) - 1 | tl(macV)]})]

padded = CryptUtils.pkcs7_pad(msgV, 16) |> IO.iodata_to_binary

payload = ";1:1MSB;0:000000"
full_msg = padded <> payload

{msgA, macA} = ClientB.create_message([{0, "0"}])

paddedA = CryptUtils.pkcs7_pad(msgA, 16) |> IO.iodata_to_binary
paddingA = String.slice(paddedA, byte_size(msgA)..-1)

targ = CryptUtils.fixed_xor(macV, :binary.bin_to_list(payload))
      |> CryptUtils.fixed_xor(macA)
      |> IO.iodata_to_binary

{_msgA2, macA2} = ClientB.create_message([{0, "0" <> paddingA <> targ}])

IO.inspect ServerB.verify({full_msg, macA2})
