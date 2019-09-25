const path = require('path');

module.exports = {
  entry: './lib/index.modern.js',
  output: {
    filename: 'main.js',
    path: path.resolve(__dirname, 'dist')
  }
};
