/**
 * Gera todos os PNGs de assets/ a partir de assets/simbolo.svg.
 *
 * Rodar só quando a marca mudar:
 *     node assets/gerar-icones.js
 *
 * Existe para que a marca tenha UMA fonte de verdade. Antes os ícones
 * eram arquivos soltos: trocar o logo significava editar oito PNGs na
 * mão e, na prática, esquecer um — foi o que aconteceu quando a marca
 * passou de "Worka" para "Workap" e o ícone da notificação continuou
 * mostrando o nome antigo.
 *
 * Cada tamanho é renderizado no Chromium no seu tamanho final (não
 * reduzido de uma imagem grande): SVG rasterizado direto fica nítido
 * em 16px, onde downscale de 512px vira borrão.
 */
var { chromium } = require('playwright');
var fs = require('fs');
var path = require('path');

var DIR = __dirname;
var SVG = fs.readFileSync(path.join(DIR, 'simbolo.svg'), 'utf8');

// fundo: null = transparente.
// Ícone de app e apple-touch levam fundo branco de propósito. O
// símbolo é verde; sobre o verde-escuro da marca ele sumiria, e o iOS
// não respeita transparência — colocaria preto atrás.
var ALVOS = [
  { arquivo: 'favicon-16.png',       w: 16,  h: 16,  fundo: null,      escala: 1.00 },
  { arquivo: 'favicon-32.png',       w: 32,  h: 32,  fundo: null,      escala: 1.00 },
  { arquivo: 'icon-192.png',         w: 192, h: 192, fundo: '#ffffff', escala: 0.82 },
  { arquivo: 'icon-512.png',         w: 512, h: 512, fundo: '#ffffff', escala: 0.82 },
  { arquivo: 'apple-touch-icon.png', w: 180, h: 180, fundo: '#ffffff', escala: 0.78 },
  // Maskable: o Android recorta até 20% de cada borda em círculo ou
  // squircle. O símbolo fica menor de propósito para caber inteiro
  // dentro da "zona segura" de 80% em qualquer recorte.
  { arquivo: 'icon-maskable-512.png', w: 512, h: 512, fundo: '#ffffff', escala: 0.60 }
];
// Os antigos logo-marca-*.png saíram: as páginas passaram a usar
// assets/simbolo.svg direto, que escala sozinho e dispensa uma versão
// por tamanho.

(async function () {
  // executablePath explícito: o Chromium deste ambiente vive fora do
  // cache padrão do Playwright, e sem isso o launch() pede um
  // `playwright install` que não é necessário.
  var binario = process.env.CHROMIUM_PATH || '/opt/pw-browsers/chromium-1194/chrome-linux/chrome';
  var browser = await chromium.launch(fs.existsSync(binario) ? { executablePath: binario } : {});
  var page = await browser.newPage();

  for (var alvo of ALVOS) {
    // O símbolo tem proporção 2,4:1. Dentro de uma caixa quadrada ele
    // é limitado pela largura; dentro de uma caixa larga, pela altura.
    // `contain` resolve os dois casos sem cálculo manual.
    var html =
      '<!doctype html><meta charset="utf-8">' +
      '<style>' +
      'html,body{margin:0;padding:0}' +
      'body{width:' + alvo.w + 'px;height:' + alvo.h + 'px;' +
      'background:' + (alvo.fundo || 'transparent') + ';' +
      'display:flex;align-items:center;justify-content:center;overflow:hidden}' +
      'svg{width:' + (alvo.escala * 100) + '%;height:' + (alvo.escala * 100) + '%;object-fit:contain}' +
      '</style>' + SVG;

    await page.setViewportSize({ width: alvo.w, height: alvo.h });
    await page.setContent(html);
    await page.screenshot({
      path: path.join(DIR, alvo.arquivo),
      omitBackground: alvo.fundo === null
    });
    console.log('gerado', alvo.arquivo, alvo.w + 'x' + alvo.h);
  }

  await browser.close();
})();
