function out=quagmire2(text,key1,key2,align,direction)
% QUAGMIRE2 Cipher encoder/decoder (ACA)
% Quagmire II uses:
%   - straight plaintext alphabet (A-Z),
%   - a keyed ciphertext alphabet derived from KEY1,
%   - an indicator key KEY2 (period = length(KEY2 after filtering)),
%   - an ALIGN letter (A-Z) in the plaintext alphabet under which KEY2 is
%     written vertically (default 'A'). The encipherments follow each letter
%     of the indicator key in turn.
%
% This implementation is a wrapper over vigenere.m (extended path) using a
% per-position ShiftStream and fixed alphabets:
%   PlainAlphabet  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
%   CipherAlphabet = keyed cipher alphabet from KEY1
%
% Only letters A-Z are processed; other characters are ignored.
%
% Syntax:
%   out = quagmire2(text,key1,key2,align,direction)
%   out = quagmire2(text,key1,key2,direction)          % align defaults to 'A'
%
% Inputs:
%   text      - char array or string scalar to encode or decode
%   key1      - keyword to build the keyed ciphertext alphabet
%   key2      - indicator keyword (period = length(key2 after filtering))
%   align     - single letter (A-Z) in the plaintext alphabet (default 'A')
%   direction - 1 to encrypt, -1 to decrypt
%
% Output (minimal + indispensable):
%   out.key1      - original key1 as provided by user
%   out.key2      - original key2 as provided by user
%   out.period    - period used (length of cleaned key2)
%   out.align     - alignment letter actually used (uppercase A-Z)
%   out.plain     - processed plaintext (A-Z only)
%   out.encrypted - processed ciphertext (A-Z only)
%
% Example:
%
% pt = 'HIDETHEGOLDINTOTHETREESTUMPSEVENTHOUSANDSTEPSDEEPTHECORALINESWAMPSBENEATHTHESILENTMOONRISE';
% out = quagmire2(pt,'LEPRACHAUN','FLOWER','A',1)
%
% out =
%
%   struct with fields:
%
%        key1: 'LEPRACHAUN'
%        key2: 'FLOWER'
%      period: 6
%       align: 'A'
%       plain: 'HIDETHEGOLDINTOTHETREESTUMPSEVENTHOUSANDSTEPSDEEPTHECORALINESWAMPSBENEATHTHESILENTMOONRISE'
%   encrypted: 'QNTLTDKHCUAFYSCKNUAOVLSWCGHJCYKIDRKXRLAZSWKKBZCULSYLROPLPAJURWONMVGAALEWQSYLSFWAAKIOZINASU'
%
% out = quagmire2(out.encrypted,'LEPRACHAUN','FLOWER','A',-1)
%
% out =
%
%   struct with fields:
%
%        key1: 'LEPRACHAUN'
%        key2: 'FLOWER'
%      period: 6
%       align: 'A'
%   encrypted: 'QNTLTDKHCUAFYSCKNUAOVLSWCGHJCYKIDRKXRLAZSWKKBZCULSYLROPLPAJURWONMVGAALEWQSYLSFWAAKIOZINASU'
%       plain: 'HIDETHEGOLDINTOTHETREESTUMPSEVENTHOUSANDSTEPSDEEPTHECORALINESWAMPSBENEATHTHESILENTMOONRISE'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Optional align handling --------------------
if nargin == 4
    direction = align;
    align = 'A';
end

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key1',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key2',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'align',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,align,direction);
clear p

if isstring(text);  text  = char(text);  end
if isstring(key1);  key1  = char(key1);  end
if isstring(key2);  key2  = char(key2);  end
if isstring(align); align = char(align); end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% -------------------- Output (original keys) --------------------
out.key1 = key1;
out.key2 = key2;

% -------------------- Clean keys (internal, A-Z only) --------------------
k1 = double(upper(key1));
k1(k1<65 | k1>90) = [];
k2 = double(upper(key2));
k2(k2<65 | k2>90) = [];

assert(~isempty(k1),'Key1 must contain at least one letter A-Z.')
assert(~isempty(k2),'Key2 must contain at least one letter A-Z.')

period = numel(k2);
out.period = period;

% -------------------- Align in plaintext alphabet (straight) --------------------
a = double(upper(align));
a(a<65 | a>90) = [];
if isempty(a)
    a = 65; % 'A'
else
    a = a(1);
end
alignChar = char(a);
out.align = alignChar;

plainAlphabet  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
alignPos = double(alignChar) - 65; % 0..25

% -------------------- Keyed ciphertext alphabet from KEY1 --------------------
k1u = unique(k1,'stable');
A = 65:90;
cipherAlphabet = char([k1u A(~ismember(A,k1u))]);

% Build inverse map for cipherAlphabet positions
posCipher = zeros(1,26); % index by (letter-65)+1, values 0..25
for i = 1:26
    posCipher(double(cipherAlphabet(i))-65+1) = i-1;
end

% -------------------- Clean text (A-Z only) --------------------
t = double(upper(text));
t(t<65 | t>90) = [];
cleanText = char(t);
clear t

if isempty(cleanText)
    if direction == 1
        out.plain = '';
        out.encrypted = '';
    else
        out.encrypted = '';
        out.plain = '';
    end
    return
end

switch direction
    case 1
        out.plain = cleanText;
    case -1
        out.encrypted = cleanText;
end

% -------------------- Build ShiftStream (0..25), cyclic over KEY2 --------------------
k2chars = char(k2);
k2pos = zeros(1,period);
for j = 1:period
    k2pos(j) = posCipher(double(k2chars(j))-65+1); % 0..25 in cipherAlphabet
end

L = numel(cleanText);
shiftStream = zeros(1,L);
for i = 1:L
    indPos = k2pos(mod(i-1,period)+1);
    shiftStream(i) = mod(indPos - alignPos, 26);
end

% -------------------- Delegate to vigenere (extended path) --------------------
tmp = vigenere(cleanText,key1,direction, ...
    'Mode','add', ...
    'PlainAlphabet',plainAlphabet, ...
    'CipherAlphabet',cipherAlphabet, ...
    'ShiftStream',shiftStream);

if direction == 1
    out.encrypted = tmp.encrypted;
else
    out.plain = tmp.plain;
end

end
