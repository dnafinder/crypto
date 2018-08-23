function out=trithemius(text,direction)
% TRITHEMIUS CIPHER encoder/decoder
% The Trithemius cipher is a polyalphabetic encryption method invented by
% the German abbot Trithemius during the Renaissance. This code is a
% sequence of shifts: the first letter is not shifted, the second is
% shifted up by 1 in the alphabet, the third by 2, etc.
% With a classical alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ, Trithemius cipher
% is equivalent to a Vigenère cipher with ABCDEFGHIJKLMNOPQRSTUVWXYZ as
% key.  
%
% Syntax: 	out=trithemius(text,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.encrypted = the coded text
%
% Examples:
%
% out=trithemius('We are discovered flee at once',1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'WEAREDISCOVEREDFLEEATONCE'
%     encrypted: 'WFCUIIOZKXFPDRRUBVWTNJJZC'
%
% out=trithemius('WFCUIIOZKXFPDRRUBVWTNJJZC',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'WFCUIIOZKXFPDRRUBVWTNJJZC'
%         plain: 'WEAREDISCOVEREDFLEEATONCE'
%
% See also vigenere, autokey, beaufort, dellaporta, gronsfeld
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

out=vigenere(text,'ABCDEFGHIJKLMNOPQRSTUVWXYZ',direction);
out=rmfield(out,'key');