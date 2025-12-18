function out=quagmire4(text,key1,key2,key3,align,direction)
% QUAGMIRE4 Cipher encoder/decoder (ACA)
% Quagmire IV employs three keywords:
%   - KEY1: builds a keyed plaintext alphabet
%   - KEY2: builds a keyed ciphertext alphabet
%   - KEY3: indicator keyword (period = length(KEY3 after filtering))
% The indicator may appear vertically under any letter of the plaintext
% alphabet (ALIGN). The encipherments follow each letter of the indicator
% key in turn.
%
% This implementation is a wrapper over vigenere.m (extended path) using a
% per-position ShiftStream.
%
% Only letters A-Z are processed; other characters are ignored.
%
% Syntax:
%   out = quagmire4(text,key1,key2,key3,align,direction)
%   out = quagmire4(text,key1,key2,key3,direction) % align='A'
%
% Inputs:
%   text      - char array or string scalar to encode/decode
%   key1      - keyword to build the keyed plaintext alphabet
%   key2      - keyword to build the keyed ciphertext alphabet
%   key3      - indicator keyword (period = length(key3 after filtering))
%   align     - single letter (A-Z) in the keyed plaintext alphabet (default 'A')
%   direction - 1 encrypt, -1 decrypt
%
% Output (minimal + indispensable):
%   out.key1      - original key1 as provided by user
%   out.key2      - original key2 as provided by user
%   out.key3      - original key3 as provided by user
%   out.period    - period used (length of cleaned key3)
%   out.align     - alignment letter actually used (uppercase A-Z)
%   out.plain     - processed plaintext (A-Z only)
%   out.encrypted - processed ciphertext (A-Z only)
%
% Example:
%
% out = quagmire4( ...
%  'HIDETHEGOLDINTOTHETREESTUMPSEVENTHOUSANDSTEPSDEEPTHECORALINESWAMPSBENEATHTHESILENTMOONRISE', ...
%  'LEPRACHAUN','GHOST','GOBLIN','A',1)
% 
% out = 
% 
%   struct with fields:
% 
%          key1: 'LEPRACHAUN'
%          key2: 'GHOST'
%          key3: 'GOBLIN'
%        period: 6
%         align: 'A'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMPSEVENTHOUSANDSTEPSDEEPTHECORALINESWAMPSBENEATHTHESILENTMOONRISE'
%     encrypted: 'OIJIHQXFRFPZTQRTKKNHSIGBSLTSDCXBWNYRMOFUGBXGVUDKYQDIJSZOOXMKMUBGEAAZFIIBOQDIGZWZFTXSKBAXGK'
% 
% out = quagmire4( ...
% 'OIJIHQXFRFPZTQRTKKNHSIGBSLTSDCXBWNYRMOFUGBXGVUDKYQDIJSZOOXMKMUBGEAAZFIIBOQDIGZWZFTXSKBAXGK', ...
% 'LEPRACHAUN','GHOST','GOBLIN','A',-1)
% 
% out = 
% 
%   struct with fields:
% 
%          key1: 'LEPRACHAUN'
%          key2: 'GHOST'
%          key3: 'GOBLIN'
%        period: 6
%         align: 'A'
%     encrypted: 'OIJIHQXFRFPZTQRTKKNHSIGBSLTSDCXBWNYRMOFUGBXGVUDKYQDIJSZOOXMKMUBGEAAZFIIBOQDIGZWZFTXSKBAXGK'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMPSEVENTHOUSANDSTEPSDEEPTHECORALINESWAMPSBENEATHTHESILENTMOONRISE'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

% -------------------- Optional align handling --------------------
if nargin == 5
    direction = align;
    align = 'A';
end

% -------------------- Input parsing --------------------
p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key1',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key2',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key3',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'align',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,key3,align,direction);
clear p

if isstring(text);  text = char(text); end
if isstring(key1);  key1 = char(key1); end
if isstring(key2);  key2 = char(key2); end
if isstring(key3);  key3 = char(key3); end
if isstring(align); align = char(align); end
assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt).')

% -------------------- Output (original keys) --------------------
out.key1 = key1;
out.key2 = key2;
out.key3 = key3;

% -------------------- Clean keys (internal, A-Z only) --------------------
k1 = double(upper(key1));
k1(k1<65 | k1>90) = [];
k2 = double(upper(key2));
k2(k2<65 | k2>90) = [];
k3 = double(upper(key3));
k3(k3<65 | k3>90) = [];

assert(~isempty(k1),'key1 must contain at least one letter A-Z.')
assert(~isempty(k2),'key2 must contain at least one letter A-Z.')
assert(~isempty(k3),'key3 must contain at least one letter A-Z.')

period = numel(k3);
out.period = period;

% -------------------- Build keyed alphabets --------------------
A = 65:90;

k1u = unique(k1,'stable');
plainAlphabet = char([k1u A(~ismember(A,k1u))]);

k2u = unique(k2,'stable');
cipherAlphabet = char([k2u A(~ismember(A,k2u))]);

% -------------------- Align letter (must be in keyed plain alphabet) --------------------
a = double(upper(align));
a(a<65 | a>90) = [];
if isempty(a)
    a = 65; % 'A'
else
    a = a(1);
end
alignChar = char(a);
assert(ismember(alignChar,plainAlphabet),'ALIGN must be a letter in the keyed plaintext alphabet.')
out.align = alignChar;

alignIdx = find(plainAlphabet==alignChar,1) - 1; % 0..25 in plainAlphabet

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

% -------------------- ShiftStream from key3 & align --------------------
% shift = posCipher(key3Letter) - posPlain(align) (mod 26)
posCipher = zeros(1,26); % map letter -> 0..25 in cipherAlphabet
for i = 1:26
    posCipher(double(cipherAlphabet(i))-65+1) = i-1;
end

k3chars = char(k3);
k3pos = zeros(1,period);
for j = 1:period
    k3pos(j) = posCipher(double(k3chars(j))-65+1);
end

L = numel(cleanText);
shiftStream = zeros(1,L);
for i = 1:L
    indPos = k3pos(mod(i-1,period)+1);
    shiftStream(i) = mod(indPos - alignIdx, 26);
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
