require "spec_helper"

describe "Ruby version check" do

  before { @load_file = "scanny/ruby_version_check.rb" }

  it "should raise exception (ruby 1.8)" do
    -> {load_with('ruby', '1.8', @load_file)}.should raise_error
  end

  it "should raise exception (ruby 1.9)" do
    -> {load_with('ruby', '1.9', @load_file)}.should raise_error
  end

  it "should raise exception (rbx 1.8 mode)" do
    -> {load_with('rbx', '1.8', @load_file)}.should raise_error
  end

  it "should not raise exception (rbx 1.9 mode)" do
    -> {load_with('rbx', '1.9', @load_file)}.should_not raise_error
  end

end

