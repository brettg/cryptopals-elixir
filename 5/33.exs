defmodule DiffieHellman do

  def gen_keys(p, g) do
    secret = :crypto.rand_uniform(0, p)
    {secret, modpow(g, secret, p)}
  end

  def session_key(privateA, publicB, p) do
    modpow(publicB, privateA, p)
  end

  defp modpow(base, pow, mod) do
    :crypto.mod_pow(base, pow, mod) |> :crypto.bytes_to_integer
  end
end

defmodule S5Ch33 do
  def test_dh(p, g) do
    for n <- 1..100 do
      {a_priv, a_pub} = DiffieHellman.gen_keys(p, g)
      {b_priv, b_pub} = DiffieHellman.gen_keys(p, g)

      s1 = DiffieHellman.session_key(a_priv, b_pub, p)
      s2 = DiffieHellman.session_key(b_priv, a_pub, p)

      if s1 != s2 do
        IO.inspect ["No!", n, p, g, a_priv, a_pub, b_priv, b_pub, s1, s2]
        exit(:bad)
      end
    end

    IO.inspect ["Test good", p, g]
  end
end

S5Ch33.test_dh(37, 5)

{nisty_p, _} = Integer.parse("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
                             16)
S5Ch33.test_dh(nisty_p, 2)
