defmodule C2E9 do

  def pkcs_pad(list, blocksize) do
    last_size = rem(length(list), blocksize)
    if last_size != 0 do
      num = blocksize - last_size
      list ++ for n <- 1..num, do: num
    else
      list
    end
  end

end

input = 'YELLOW SUBMARINE'
blocksize = 20
# expected = 'YELLOW SUBMARINE\x04\x04\x04\x04'
expected = 'YELLOW SUBMARINE' ++ [4, 4, 4, 4]

result = C2E9.pkcs_pad(input, blocksize)
IO.inspect expected
IO.inspect result
IO.inspect result == expected

IO.inspect C2E9.pkcs_pad(input, 16)
IO.inspect input == C2E9.pkcs_pad(input, 16)
