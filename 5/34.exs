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

  def columnize([]), do: []
  def columnize(l) do
    heads = heads(l)
    if Enum.empty?(heads), do: [], else: [heads | columnize(tails(l))]
  end
  def tails([]), do: []
  def tails([[] | cdr]), do: tails(cdr)
  def tails([car | cdr]) do
    [tl(car) | tails(cdr)]
  end
  def heads([]), do: []
  def heads([[] | cdr]), do: heads(cdr)
  def heads([car | cdr]) do
    [hd(car) | heads(cdr)]
  end
end

defmodule DiffieHellman do
  def gen_keys(p, g) do
    secret = :crypto.rand_uniform(0, p)
    {secret, modpow(g, secret, p)}
  end

  def session_key(privateA, publicB, p), do: modpow(publicB, privateA, p)

  defp modpow(base, pow, mod), do: :crypto.mod_pow(base, pow, mod) |> :crypto.bytes_to_integer
end

defmodule S5Ch34 do
  # We could concat, but splitting it apart doesn't seem like a crucial part of the exercise...
  def msg_and_iv(session_key, msg) do
    iv = CryptUtils.rand_bytes(16)
    {CryptUtils.aes_cbc_encrypt(session_key_key(session_key), iv, msg), iv}
  end

  def decrypt_msg(session_key, msg, iv) do
    CryptUtils.aes_cbc_decrypt(session_key_key(session_key), iv, msg)
  end

  def session_key_key(session_key) do
    Integer.digits(session_key, 256)
    |> IO.iodata_to_binary
    |> (&(:crypto.hash(:sha, &1))).()
    |> :binary.bin_to_list
    |> Enum.slice(0..15)
  end
end

defmodule S5Ch34A do
  @p Integer.parse("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
     |> elem(0)
  @g :rand.uniform(5) + 2
  @keys DiffieHellman.gen_keys(@p, @g)
  @message 'This is the message that is made of words, mostly.'

  # User gets A to emit request for B with p, g, pubA
  def init do
    {@p, @g, elem(@keys, 1)}
  end

  # B->A
  # Send "B"
  # Return A's Message:
  # Send AES-CBC(SHA0(s)[0:16], iv=random(16), msg) + iv
  def rec_pub_key(pubB) do
    Process.put(:a_pub_b, pubB)
    S5Ch34.msg_and_iv(session_key, @message)
  end

  # B->A
  # Send B's echo
  def rec_echo(msgB, iv) do
    S5Ch34.decrypt_msg(session_key, msgB, iv) == @message
  end

  defp session_key, do: DiffieHellman.session_key(elem(@keys, 0), Process.get(:a_pub_b), @p)
end

defmodule S5Ch34B do
  # A->B
  # Send "p", "g", "A"
  # Return "B"
  def rec_init(p, g, pubA) do
    Process.put(:b_p, p)
    Process.put(:b_g, g)
    Process.put(:b_pub_a, pubA)

    {b, pubB} = DiffieHellman.gen_keys(p, g)
    Process.put(:b_key, b)
    Process.put(:b_pub_key, pubB)

    pubB
  end

  # A->B
  # Send A's msg
  # Return B's echo:
  # Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  def rec_msg(msgA, iv) do
    S5Ch34.msg_and_iv(session_key, S5Ch34.decrypt_msg(session_key, msgA, iv))
  end

  defp session_key do
    DiffieHellman.session_key(Process.get(:b_key),
                              Process.get(:b_pub_a),
                              Process.get(:b_p))
  end
end

{p, g, pubA} = S5Ch34A.init
pubB = S5Ch34B.rec_init(p, g, pubA)
{msgA, ivA} = S5Ch34A.rec_pub_key(pubB)
{msgB, ivB} = S5Ch34B.rec_msg(msgA, ivA)
IO.inspect ['Normal interchange works:', S5Ch34A.rec_echo(msgB, ivB)]

{p, g, _} = S5Ch34A.init
_ = S5Ch34B.rec_init(p, g, p)
{msgA, ivA} = S5Ch34A.rec_pub_key(p)
{msgB, ivB} = S5Ch34B.rec_msg(msgA, ivA)
IO.inspect ['MITM interchange works:', S5Ch34A.rec_echo(msgB, ivB)]

decrypted = CryptUtils.aes_cbc_decrypt(S5Ch34.session_key_key(0), ivA, msgA)
IO.inspect ['Decrypted message:', decrypted]
