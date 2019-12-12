defmodule TestCall.MixProject do
  use Mix.Project

  def project do
    [
      app: :test_call,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:aepp_sdk_elixir, git: "https://github.com/aeternity/aepp-sdk-elixir.git", tag: "v0.5.2"}
    ]
  end
end
