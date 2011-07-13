require 'spec_helper'

module Scanny::Checks
  class SimpleCheck
    include Helpers
  end

  describe Helpers do
    before :all do
      @parser = RubyParser.new
      @check  = SimpleCheck.new
    end

    describe 'convert sexp nodes to ruby hash' do
      it 'raise a ConversionException if node is not a hash' do
        node = @parser.parse("[1,2,3]")
        lambda{ @check.node_to_hash(node) }.should raise_error(ConversionError)
      end

      it 'raise a ConversionException if node is not a Sexp object' do
        lambda{ @check.node_to_hash("foo") }.should raise_error(ConversionError)
      end

      it 'converts simple hash' do
        input = "{:key1 => 'value1', :key2 => 'value2', :key3 => :value3}"
        expected = eval(input)
        node = @parser.parse(input)
        @check.node_to_hash(node).should == expected
      end

      it 'converts a complex hashes'
    end
  end
end
