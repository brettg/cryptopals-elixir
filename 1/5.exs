use Bitwise

defmodule S1C5 do
  def rep_xor(bytes, key) do
    key_len = length(key)
    key_tup = List.to_tuple(key)
    bytes
    |> Enum.with_index
    |> Enum.map(fn ({b, idx}) ->  b ^^^ elem(key_tup, rem(idx, key_len)) end)
  end
end

input = 'Burning \'em, if you ain\'t quick and nimble
I go crazy when I hear a cymbal'

key = 'ICE'

target = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

IO.inspect [String.length(target), target]

out_hex = S1C5.rep_xor(to_charlist(input), key)
|> IO.iodata_to_binary
|> Base.encode16(case: :lower)

IO.inspect [String.length(out_hex), out_hex]

IO.inspect ['c', target == out_hex]
