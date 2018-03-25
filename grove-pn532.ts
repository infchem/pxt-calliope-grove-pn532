/**
 * Functions for the Seeedstudio Grove NFC.
 * WIP: Reads NDEF text records <=11 chars from ISO14443-3A / Mifare
 *
 * @author Mirek Hancl
 */


//% weight=2 color=#1174EE icon="\uf086" block="Grove NFC Tag"
//% parts="grove_pn532"
namespace grove_pn532 {
    const ADDRESS = 0x24;
	let targetID = 0;
	// if ISO14443-A / Mifare target found, targetID will be 1
	let running = false;
	// if PN532 isn't running, no reading will be possible


function wakeup() {
    // just to be sure...
    pins.i2cWriteNumber(0x24, 0, NumberFormat.UInt8LE)
    basic.pause(100)
    // SAMConfiguration: normal mode
    let wakeup: number[] =[0x00, 0x00, 0xFF, 0x03, 0xFD, 0xD4, 0x14, 0x01, 0x17, 0x00];
    let inputFrame = pins.createBuffer(10);
    for (let i = 0; i <= inputFrame.length - 1; i++) {
        inputFrame.setNumber(NumberFormat.UInt8LE, i, wakeup[i]);
    }
    pins.i2cWriteBuffer(0x24, inputFrame);
    basic.pause(100);

    let valid = true;
    // check ack frame
    let ack: number[] =[0x01, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00];
    let outputFrame = pins.i2cReadBuffer(0x24, 7);
    for (let i = 0; i <= ack.length - 1; i++) {
        if (outputFrame.getNumber(NumberFormat.UInt8LE, i) != ack[i]) {
            valid = false;
            break;
        }
    }
    // check response
    let wakeupOK: number[] =[0x01, 0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD5, 0x15, 0x16]
    outputFrame = pins.i2cReadBuffer(0x24, 9);
    for (let i = 0; i <= ack.length - 1; i++) {
        if (outputFrame.getNumber(NumberFormat.UInt8LE, i) != wakeupOK[i]) {
            valid = false;
            break;
        }
    }
    // if something went wrong...
    if (!valid) {
        // basic.showIcon(IconNames.Sad);
        // basic.pause(500);
        // basic.clearScreen();
    } else {
        running = true;
    }
    basic.pause(100);
}

function findPassiveTarget() {
     targetID = 0;
    // InListPassiveTarget: 1 target, 106 kbps type A (ISO14443 Type A)
    let listTarget: number[] =[0x00, 0x00, 0xFF, 0x04, 0xFC, 0xD4, 0x4A, 0x01, 0x00, 0xE1, 0x00];
    let inputFrame = pins.createBuffer(11);
    for (let i = 0; i <= inputFrame.length - 1; i++) {
        inputFrame.setNumber(NumberFormat.UInt8LE, i, listTarget[i]);
    }
    pins.i2cWriteBuffer(0x24, inputFrame);
    basic.pause(100);

    // check ack frame
    let ack: number[] =[0x01, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00];
    let outputFrame = pins.i2cReadBuffer(0x24, 7);
    for (let i = 0; i <= ack.length - 1; i++) {
        if (outputFrame.getNumber(NumberFormat.UInt8LE, i) != ack[i]) {
            break;
        }
    }
    basic.pause(100);

    // check response
    outputFrame = pins.i2cReadBuffer(0x24, 22);
    if (outputFrame[0] == 0x01 && outputFrame[8] == 0x01) {
        targetID = 1;
    }

    // if something went wrong...
    // if (targetID == 0) {
        // basic.showIcon(IconNames.Sad);
        // basic.pause(500);
        // basic.clearScreen();
    // }
}

/**
     * Read NDEF text record <10 bytes from Mifare tag.
     */
    //% weight=209
    //% blockId=grove_pn532_textrecord block="read text message in NFC tag"
    //% parts="grove_pn532"
export function readNDEFText(): string {
    if (!running) {
        wakeup();
        basic.pause(10);
        // we have to wait...
    }
    // if (targetID == 0) {
    findPassiveTarget();
    //    basic.pause(10);
    // }
    let textMessage = "";
    if (targetID == 1) {
        // InDataExchange: target 1, 16 bytes reading, page 04
        // ToDo: read text message > 5 bytes
        let readData: number[] =[0x00, 0x00, 0xFF, 0x05, 0xFB, 0xD4, 0x40, 0x01, 0x30, 0x04, 0xB7, 0x00];
        let inputFrame = pins.createBuffer(12);
        for (let i = 0; i <= inputFrame.length - 1; i++) {
            inputFrame.setNumber(NumberFormat.UInt8LE, i, readData[i]);
        }
        pins.i2cWriteBuffer(0x24, inputFrame);
        basic.pause(100);

        // check ack frame
        let valid = true;
        let ack: number[] =[0x01, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00];
        let outputFrame = pins.i2cReadBuffer(0x24, 7);
        for (let i = 0; i <= ack.length - 1; i++) {
            if (outputFrame.getNumber(NumberFormat.UInt8LE, i) != ack[i]) {
                valid = false;
                break;
            }
        }
        basic.pause(100);
        if (valid) {
            // check response
            outputFrame = pins.i2cReadBuffer(0x24, 32);
            for (let k = 0; k < outputFrame.length; k++) {
            }

            // RDY ? 
            if (outputFrame[0] == 0x01) {
                let startByte = -1;
                for (let l = 8; l < outputFrame.length; l++) {
                    //where's the first NDEF message with message type == text?
                    if (outputFrame.getNumber(NumberFormat.UInt8LE, l) == 0x03 && outputFrame.getNumber(NumberFormat.UInt8LE, l + 5) == 0x54) {
                        startByte = l + 9;
                        // we don't need the T and language code stuff...
                        break;
                    } else {
                        startByte = -1;
                    }
                }
                if (startByte != -1) {
                    while (outputFrame.getNumber(NumberFormat.UInt8LE, startByte) != 0xFE && startByte < outputFrame.length) {
                        // read the text message until terminator tag or end of block
                        //ToDo: read UTF-8
                        textMessage += String.fromCharCode(outputFrame.getNumber(NumberFormat.UInt8LE, startByte));
                        startByte++;
                    }
                }
            }
        }
    }
    return textMessage;
}
}