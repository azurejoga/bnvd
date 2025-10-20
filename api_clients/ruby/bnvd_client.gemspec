Gem::Specification.new do |spec|
  spec.name          = "bnvd_client"
  spec.version       = "1.0.0"
  spec.authors       = ["BNVD Team"]
  spec.email         = ["contato@bnvd.org"]

  spec.summary       = "Cliente oficial para a API do BNVD"
  spec.description   = "Cliente Ruby para a API do Banco Nacional de Vulnerabilidades Cibernéticas (BNVD)"
  spec.homepage      = "https://bnvd.org"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/azurejoga/bnvd/tree/main/api_clients/ruby"
  spec.metadata["changelog_uri"] = "https://github.com/azurejoga/bnvd/tree/main/api_clients/ruby/CHANGELOG.md"

  spec.files = Dir["lib/**/*", "README.md", "LICENSE.txt"]
  spec.require_paths = ["lib"]

  spec.add_dependency "json", "~> 2.6"
  
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "webmock", "~> 3.18"
end
