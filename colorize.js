const { Jimp } = require('jimp');

async function colorize() {
  try {
    const image = await Jimp.read('assets/logo.png');
    // Iterate over all pixels
    image.scan(0, 0, image.bitmap.width, image.bitmap.height, function(x, y, idx) {
      const a = this.bitmap.data[idx + 3]; // Alpha channel

      // If the pixel is visible (not transparent)
      if (a > 10) { 
        // Change color to AegisWeb Accent Blue (#3B82F6)
        this.bitmap.data[idx + 0] = 59;  // Red
        this.bitmap.data[idx + 1] = 130; // Green
        this.bitmap.data[idx + 2] = 246; // Blue
      }
    });

    await image.write('assets/logo-light.png');
    console.log('Successfully created assets/logo-light.png');
  } catch (error) {
    console.error('Error processing image:', error);
  }
}

colorize();
