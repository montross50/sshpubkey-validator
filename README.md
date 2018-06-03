# SSHPubKeyValidator

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis]][link-travis]
[![Coverage Status][ico-scrutinizer]][link-scrutinizer]
[![Quality Score][ico-code-quality]][link-code-quality]
[![Total Downloads][ico-downloads]][link-downloads]

This package serves to take in an ssh-rsa key and validate whether the key is in a valid format. I'm sure there is a better way to do this but I couldn't find anything better in pure php.

## Install

Via Composer

``` bash
$ composer require montross50/SSHPubKeyValidator
```

## Usage

``` php
$skeleton = new montross50\SSHPubKeyValidator();
echo $skeleton->echoPhrase('Hello, League!');
```

## Change log

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Testing

``` bash
$ composer test
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) and [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) for details.

## Security

If you discover any security related issues, please email sch43228@gmail.com instead of using the issue tracker.

## Credits

- [][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

[ico-version]: https://img.shields.io/packagist/v/montross50/SSHPubKeyValidator.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-travis]: https://img.shields.io/travis/montross50/SSHPubKeyValidator/master.svg?style=flat-square
[ico-scrutinizer]: https://img.shields.io/scrutinizer/coverage/g/montross50/SSHPubKeyValidator.svg?style=flat-square
[ico-code-quality]: https://img.shields.io/scrutinizer/g/montross50/SSHPubKeyValidator.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/montross50/SSHPubKeyValidator.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/montross50/SSHPubKeyValidator
[link-travis]: https://travis-ci.org/montross50/SSHPubKeyValidator
[link-scrutinizer]: https://scrutinizer-ci.com/g/montross50/SSHPubKeyValidator/code-structure
[link-code-quality]: https://scrutinizer-ci.com/g/montross50/SSHPubKeyValidator
[link-downloads]: https://packagist.org/packages/montross50/SSHPubKeyValidator
[link-author]: https://github.com/montross50
[link-contributors]: ../../contributors