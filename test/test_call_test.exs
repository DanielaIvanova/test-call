defmodule TestCallTest do
  use ExUnit.Case
  doctest TestCall

  test "greets the world" do
    assert TestCall.hello() == :world
  end
end
