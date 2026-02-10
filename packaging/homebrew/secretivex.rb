class Secretivex < Formula
  desc "Cross-platform, high-throughput SSH agent platform"
  homepage "https://github.com/sarveshkapre/secretiveX"
  license "MIT"

  # Head-only for now; once we cut a tagged release, add a stable url + sha256.
  head "https://github.com/sarveshkapre/secretiveX.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--release", "--locked", "--workspace"

    bin.install "target/release/secretive-agent"
    bin.install "target/release/secretive-client"
    bin.install "target/release/secretive-bench"
  end

  test do
    assert_match(/\d+\.\d+\.\d+/, shell_output("#{bin}/secretive-agent --version").strip)
    assert_match(/\d+\.\d+\.\d+/, shell_output("#{bin}/secretive-client --version").strip)
  end
end
