use Bitwise

defmodule S2C10 do

  def aes_cbc_encrypt(_key, _iv, []), do: []
  def aes_cbc_encrypt(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    encrypted = aes_ecb_encrypt(key, fixed_xor(iv, pkcs_pad(block, size)))
    encrypted ++ aes_cbc_encrypt(key, encrypted, rest)
  end

  def aes_cbc_decrypt(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    decrypted = fixed_xor(aes_ecb_decrypt(key, block), iv)
    if Enum.empty?(rest) do
      pkcs_unpad(decrypted)
    else
      decrypted ++ aes_cbc_decrypt(key, block, rest)
    end
  end

  def aes_ecb_encrypt(key, data) do
    :crypto.block_encrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
  end

  def aes_ecb_decrypt(key, data) do
    :crypto.block_decrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
  end

  def read_64(path) do
    path
    |> File.read!
    |> Base.decode64!(ignore: :whitespace)
    |> :binary.bin_to_list
  end

  def to_64(list) do
    list |> IO.iodata_to_binary |> Base.encode64
  end

  def fixed_xor(l1, l2) do
    Enum.zip(l1, l2)
    |> Enum.map(fn ({n1, n2}) -> n1 ^^^ n2 end)
  end

  def pkcs_pad(list, blocksize) do
    num = blocksize - length(list)
    if num > 0 do
      list ++ pkcs_padding(num)
    else
      list
    end
  end

  def pkcs_unpad(list) do
    size = length(list)
    num = List.last(list)
    if num > 0 and num < size and Enum.slice(list, size - num, num) == pkcs_padding(num) do
      Enum.slice(list, 0, size - num)
    else
      list
    end
  end

  def pkcs_padding(num) do
    for _ <- 1..num, do: num
  end
end


key = 'YELLOW SUBMARINE'
zero_ev = for _ <- 0..(length(key) - 1), do: 0

# seven_txt = S2C10.read_64("1/7.txt")
# decrypted = S2C10.aes_ecb_decrypt(key, seven_txt)
# seven_reencrypted_64 = S2C10.aes_cbc_encrypt(key, zero_ev, decrypted) |> S2C10.to_64
# raw_ten_text = File.read!("2/10.txt") |> String.split |> Enum.join
# IO.inspect raw_ten_text == reencrypted_64

ten_txt =  S2C10.read_64("2/10.txt")

IO.inspect S2C10.aes_cbc_decrypt(key, zero_ev, ten_txt)
