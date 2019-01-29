function out=gronsfeld(text,key,direction)
% GRONSFELD Cipher encoder/decoder
% Gronsfeld encryption uses the Vigenere method, the difference being that
% the key is directly numeric, no need to calculate the rank of the letters
% of the key in the alphabet. However, the corresponding shifts have to be
% applied, so the Gronsfeld method approaches a multi-shift encryption.
%
% Syntax: 	out=gronsfeld(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is a characters array of the digits used as key.
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.encrypted = the coded text
%
% Examples:
%
% out=gronsfeld('Hide the gold into the tree stump','1264587895663',1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: '1264587895663'
%     encrypted: 'IKJIYPLOXQJOQUQZLJBYMNXZAPQ'
%
% out=gronsfeld('IKJIYPLOXQJOQUQZLJBYMNXZAPQ','1264587895663',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'IKJIYPLOXQJOQUQZLJBYMNXZAPQ'
%           key: '1264587895663'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also autokey, beaufort, dellaporta, trithemius, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

out=vigenere(text,char(double(key)+17),direction);
out.key=key;