/**
 * Functions for the Seeedstudio Grove NFC.
 * WIP: Reads NDEF text records from ISO14443-3A / Mifare
 *
 * @author Mirek Hancl
 */

//% weight=2 color=#1174EE icon="\uf086" block="Grove NFC Tag"
//% parts="grove_pn532"
namespace grove_pn532 {
    /** Set this to true if you want serial output. */
    const DEBUG_SERIAL = false;

    const ADDRESS = 0x24;

    let targetID = 0;
    // if ISO14443-A / Mifare target found, targetID will be 1
    let running = false;
    // if PN532 isn't running, no reading will be possible

	/** 
	 * ACK frame as specified in the PN532 User Manual (Page 30).
	 * Used for synchronization or 
	 * to check if a previous frame has been recieved successfully.
	 */
    const ACK_FRAME: number[] = [0x01, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00];


	/**
	 * Compares an array against output of the same length.
	 * @param arr The array to compare the device output against.
	 * @returns true if the output matches the passed array, false otherwise
	 */
    function checkOutput(arr: number[]): boolean {
        let outputFrame = pins.i2cReadBuffer(ADDRESS, arr.length);
        for (let i = 0; i <= arr.length - 1; i++) {
            if (outputFrame.getNumber(NumberFormat.UInt8LE, i) != arr[i]) {

                //Printing the array that was recieved.
                if(DEBUG_SERIAL) {
                    basic.pause(100);
                    serial.writeLine("Now printing requested buffer contents:")
                    for (let i = 0; i < outputFrame.length; i++) {
                        serial.writeString(outputFrame.getNumber(NumberFormat.UInt8LE, i) + " ")
                    }
                    serial.writeString("\n");
                }

                return false;
            }
        }
        basic.pause(100);

        return true;
    }

	/**
	 * Writes an array as buffer to the target device.
	 * The array should be a normal information frame 
	 * with the format specified in the PN532 User Manual (Page 28).
	 * @param arr The array to write to the device as a buffer.
	 */
    function writeBuffer(arr: number[]) {
        let inputFrame = pins.createBuffer(arr.length);
        for (let i = 0; i <= inputFrame.length - 1; i++) {
            inputFrame.setNumber(NumberFormat.UInt8LE, i, arr[i]);
        }
        pins.i2cWriteBuffer(ADDRESS, inputFrame);
        basic.pause(100);
    }

	/**
	 * Reads 16 bytes of data from the device.
	 * @param address The address to read from
	 * @returns A buffer filled with the data we recieved. null if reading failed.
	 */
    function read16Bytes(address: number) {

        // InDataExchange: target 1 (0x01), 16 bytes reading (0x30)
        let readData: number[] = [0x00, 0x00, 0xFF, 0x05, 0xFB, 0xD4, 0x40, 0x01, 0x30, address, 0xBB - address, 0x00];

        if(DEBUG_SERIAL) serial.writeLine("Reading from address " + address);

        writeBuffer(readData);

        // check ack frame
        if (!checkOutput(ACK_FRAME)) {
            if(DEBUG_SERIAL) serial.writeLine("ACK check failed!");
            return null;
        }

        if(DEBUG_SERIAL) serial.writeLine("Getting device outputFrame");

        // we'll receive an normal information frame (see 6.2.1.1 in UM) with 16 bytes of packet data
        let outputFrame = pins.i2cReadBuffer(ADDRESS, 27);

        if (outputFrame[0] != 0x01) {
            if(DEBUG_SERIAL) serial.writeLine("outputFrame[0] != 0x01");
            return null;
        }

        if(DEBUG_SERIAL) serial.writeLine("Got outputBuffer!");

        return outputFrame;
    }

	/**
	 * Waking up the device and
	 * Disabling the Security Access Module (SAM) since we don't use it.
	 */
    function wakeup() {
        // just to be sure...
        pins.i2cWriteNumber(ADDRESS, 0, NumberFormat.UInt8LE);
        basic.pause(100);

        // SAMConfiguration: normal mode (Page 89)
        // Mode 0x01 disables SAM
        const wakeup: number[] = [0x00, 0x00, 0xFF, 0x03, 0xFD, 0xD4, 0x14, 0x01, 0x17, 0x00];
        writeBuffer(wakeup);

        // check ack
        let validAck = checkOutput(ACK_FRAME);

        // check response
        const wakeupOK: number[] = [0x01, 0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD5, 0x15, 0x16];
        let validWakeupOK = checkOutput(wakeupOK);

        // if something went wrong...
        if (validAck && validWakeupOK) {
            running = true;
        } else {
            if(DEBUG_SERIAL) serial.writeLine("Wakeing up failed!");
        }
    }

    function findPassiveTarget() {
        targetID = 0;

        // InListPassiveTarget: 1 target, 106 kbps type A (ISO14443 Type A)
        const listTarget: number[] = [0x00, 0x00, 0xFF, 0x04, 0xFC, 0xD4, 0x4A, 0x01, 0x00, 0xE1, 0x00];
        writeBuffer(listTarget);

        // check ack frame
        checkOutput(ACK_FRAME);

        // check response
        let outputFrame = pins.i2cReadBuffer(ADDRESS, 22);
        if (outputFrame[0] == 0x01 && outputFrame[8] == 0x01) {
            targetID = 1;
        }
    }

	/**
	 * Read NDEF text record from Mifare Ultralight tag.
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

        findPassiveTarget();

        let textMessage = "";
        if (targetID == 1) { //Did we find a device?

            let outputFrame = read16Bytes(0x04);
            if (outputFrame != null) {
                let startByte = -1;
                let messageLength = -1;
                // skip RDY, PREAMBLE, START CODE, LEN, LCS, TFI, COMMAND CODE, STATUS
                // skip also DCS, POSTAMBLE at the end
                for (let l = 9; l < outputFrame.length - 2; l++) {
                    //where's the first NDEF message with message type == text?
                    if (outputFrame.getNumber(NumberFormat.UInt8LE, l) == 0x03 &&
                        outputFrame.getNumber(NumberFormat.UInt8LE, l + 5) == 0x54) {

                        //The last 6 bits (0x3F) of the status byte are the length of the IANA language code field 
                        // Text length = messageLength - language code length - 1 
                        messageLength = outputFrame.getNumber(NumberFormat.UInt8LE, l + 4) - 
                                       (outputFrame.getNumber(NumberFormat.UInt8LE, l + 6) & 0x3F) - 1;

                        startByte = l + 7 + (outputFrame.getNumber(NumberFormat.UInt8LE, l + 6) & 0x3F);

                        if(DEBUG_SERIAL) {
                            serial.writeLine("Total length to read: " + outputFrame.getNumber(NumberFormat.UInt8LE, l + 4));
                            serial.writeLine("language code length: " + (outputFrame.getNumber(NumberFormat.UInt8LE, l + 6) & 0x3F));
                            serial.writeLine("got length " + messageLength + " and startByte " + startByte);
                        }

                        break;
                    }
                }

                if (startByte != -1 && messageLength > 0) {

                    let amountRead = 27 - startByte - 2; // 27 bytes normal information frame w/ 16 bytes packet data, whereof 2 for postamble and data checksum
                    let currentPage = 0x04;

                    while (true) {

                        if(DEBUG_SERIAL) serial.writeLine("reading byte " + startByte + " from page " + currentPage);

                        if (startByte >= outputFrame.length - 2) {
                            //We need to read more bytes

                            messageLength -= amountRead;
                            
                            if(DEBUG_SERIAL) serial.writeLine("messageLength left: " + messageLength);
                            
                            if (messageLength <= 0) {
                                //Reached the end of input.
                                break;
                            }

                            startByte = 9;
                            currentPage += 0x04; //We read 4 pages, read the next ones now
                            if(DEBUG_SERIAL) serial.writeLine("Getting a new page with address " + currentPage);
                            outputFrame = read16Bytes(currentPage);
                            amountRead = 16;

                            if (outputFrame == null) {
                                //Something has gone terribly wrong. abort!
                                if(DEBUG_SERIAL) serial.writeLine("error reading from address " + currentPage + "! Aborting");
                                break;
                            }

                        }

                        if (outputFrame.getNumber(NumberFormat.UInt8LE, startByte) == 0xFE) {
                            //We reached the end of our record. Stop reading.
                            //Theoretically we should not reach here since we read till exactly the character before
                            if(DEBUG_SERIAL) serial.writeLine("Found end of record (0xFE)! This shouldnt happen..");
                            break;
                        }

                        //ToDo: read UTF-8
                        textMessage += String.fromCharCode(outputFrame.getNumber(NumberFormat.UInt8LE, startByte));
                        startByte++;
                        if(DEBUG_SERIAL) serial.writeLine("Got char " + String.fromCharCode(outputFrame.getNumber(NumberFormat.UInt8LE, startByte)));
                    }
                }
            }
        }
        if(DEBUG_SERIAL) serial.writeLine("The found textMessage is\n" + textMessage);
        return textMessage;
    }
}
