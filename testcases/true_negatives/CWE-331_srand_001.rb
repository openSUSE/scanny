# 2011/09/12: slms/webapp/lib/slms/utils.rb
#
#  Copyright (c) 2009 Novell, Inc.
#  All Rights Reserved.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License as
#  published by the Free Software Foundation; version 2.1 of the license.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this library; if not, contact Novell, Inc.
#
#  To contact Novell about this file by physical or electronic mail,
#  you may find current contact information at www.novell.com

require 'uri'
require 'command_line'

module Slms
  # FIXME either make this 'class RepoSigner' or make this static
  # Slms::Utils::sing_repo method
  class Utils
    attr_accessor :errors

    def initialize
      @errors = []
    end

    # Returns a randomly generated string, with a default length of 8 characters.
    # A user_friendly salt does not include the numbers '0' and '1' since they are
    # often confused by users with the letters 'O' and 'l'.
    def self.make_random_string(length=8, user_friendly=false)
      # Initialize the pseudorandom number generator to a random state
      # See more at http://thetoms-random-thoughts.blogspot.com/2008/06/ruby-and-openid-library.html
      # and the `srand` documentation
      srand # TESTCASE: CWE-331
      chars = user_friendly ?
        'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789' :
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

      random_string = ''
      length.downto(1) { random_string << chars[rand(chars.length - 1)] }
      random_string
    end
  end
end
