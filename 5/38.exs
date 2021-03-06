
defmodule Words do
  @path "/usr/share/dict/words"

  def all, do: File.read!(@path) |> String.split
end

defmodule Shared do
  @n Integer.parse("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
     |> elem(0)
  @g 2
  @k 3
  @i "emaily@examples.orgcom"
  @p "perambulant"

  def n, do: @n
  def g, do: @g
  def k, do: @k
  def i, do: @i
  def p, do: @p

  def intbytes(int), do: Integer.digits(int, 256) |> IO.iodata_to_binary
  def sha256_int(msg), do: :crypto.hash(:sha256, msg) |> :crypto.bytes_to_integer

  def mod_pow(base, pow, mod), do: :crypto.mod_pow(base, pow, mod) |> :crypto.bytes_to_integer
  def mod_pown(base, pow), do: mod_pow(base, pow, @n)

  def gen_u(pub_a, pub_b), do: sha256_int(intbytes(pub_a) <> intbytes(pub_b))
  def gen_hmac(s, salt_bytes) do
    k = :crypto.hash(:sha256, Shared.intbytes(s))
    :crypto.hmac(:sha256, k, salt_bytes)
  end
end

defmodule Server do
  @salt :crypto.rand_uniform(0, 0xFFFFFFFF)
  @salt_bytes Shared.intbytes(@salt)
  @x Shared.sha256_int(@salt_bytes <> Shared.p)
  @v Shared.mod_pown(Shared.g, @x)

  @private_key :crypto.rand_uniform(0, Shared.n)
  @pub_key Shared.mod_pown(Shared.g, @private_key)

  @u :crypto.rand_uniform(0, 0xFFFFFFFF)

  def init(email, client_pub) do
    Process.put(:server_client_pub, client_pub)

    if email == Shared.i, do: {@salt, @pub_key, @u}
  end

  def validate(hmac) do
    # S = (A * v ** u)**b % n
    s = Shared.mod_pown(client_pub * Shared.mod_pown(@v, @u), @private_key)
    hmac == Shared.gen_hmac(s, @salt_bytes)
  end

  defp client_pub, do: Process.get(:server_client_pub)
end

defmodule Client do
  @private_key :crypto.rand_uniform(0, Shared.n)
  @pub_key Shared.mod_pown(Shared.g, @private_key)

  def login(password, server \\ Server) do
    {salt, server_pub, u} = server.init(Shared.i, @pub_key)
    salt_bytes = Shared.intbytes(salt)

    x = Shared.sha256_int(salt_bytes <> password)
    s = Shared.mod_pown(server_pub, @private_key + u * x)

    server.validate(Shared.gen_hmac(s, salt_bytes))
  end
end

defmodule MITM do
  def init(_, client_pub) do
    Process.put(:mitm_client_pub, client_pub)

    # We need know g for this to work anyway, right?
    {0, Shared.g, 1}
  end

  def validate(hmac) do
    found = Enum.find(Words.all, fn(w) ->
      match_word(hmac, w)
    end)
    IO.inspect ['matched password', found]

    true
  end

  def match_word(hmac, word) do
    x = Shared.sha256_int(<<0>> <> word)
    v = Shared.mod_pown(Shared.g, x)
    s = Shared.mod_pown(client_pub * v, 1)
    hmac == Shared.gen_hmac(s, <<0>>)
  end

  defp client_pub, do: Process.get(:mitm_client_pub)
end

IO.inspect ["bad password", Client.login("frogs")]
IO.inspect ["correct password:", Client.login(Shared.p)]

IO.inspect ["MITM:", Client.login(Shared.p, MITM)]
