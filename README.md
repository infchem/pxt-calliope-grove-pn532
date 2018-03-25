# pxt-calliope-grove-pn532 - Seeedstudio Grove NFC

Read text records in ISO 14443-3A RFID chips like Mifare Ultralight with MakeCode, your micro:bit or Calliope mini.

## MakeCode Blocks Example
* English
![alt text](https://github.com/infchem/pxt-calliope-grove-pn532/raw/master/mc_example_en.png "MakeCode Blocks Example English")
* German 
![alt text](https://github.com/infchem/pxt-calliope-grove-pn532/raw/master/mc_example_de.png "MakeCode Blocks Example German")

## MakeCode JavaScript Example

```javascript
basic.forever(() => {
    basic.showString(grove_pn532.readNDEFText())
})
```

## License

Copyright (C) 2017 Mirek Hancl

Licensed under the MIT License (MIT). See LICENSE file for more details.

## Supported targets

* for PXT/microbit
* for PXT/calliope
