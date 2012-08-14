require "spec_helper"

module Scanny::Checks
  describe HTTPRequestCheck do
    before do
      @runner = Scanny::Runner.new(HTTPRequestCheck.new)
      @message =  "Connecting to the server without encryption " +
          "can facilitate sniffing traffic"
      @issue = issue(:low, @message, 441)
    end

    it "reports \"Net::HTTP.new('http://example.com/')\" correctly" do
      @runner.should  check("Net::HTTP.new('http://example.com/')").
                      with_issue(@issue)
    end

    it "reports \"Net::HTTP::Get.new('http://example.com/')\" correctly" do
      @runner.should  check("Net::HTTP::Get.new('http://example.com/')").
                      with_issue(@issue)
    end

    it "reports \"Net::HTTP::Post.new('http://example.com/')\" correctly" do
      @runner.should  check("Net::HTTP::Post.new('http://example.com/')").
                      with_issue(@issue)
    end

    it "reports \"Net::HTTP::Method.new('http://example.com/')\" correctly" do
      @runner.should  check("Net::HTTP::Method.new('http://example.com/')").
                      with_issue(@issue)
    end

    it "reports \"Net::HTTP::Proxy('proxy.example.com', 8080)\" correctly" do
      @runner.should  check("Net::HTTP::Proxy('proxy.example.com', 8080)").
                      with_issue(@issue)
    end
  end
end
