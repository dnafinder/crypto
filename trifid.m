function out=trifid(text,key,period,direction)
% TRIFID Cipher encoder/decoder
% The Trifid cipher is a classical cipher invented by Félix Delastelle and
% described in 1902. Extending the principles of Delastelle's earlier
% Bifid cipher, it combines the techniques of fractionation and
% transposition to achieve a certain amount of confusion and diffusion:
% each letter of the ciphertext depends on three letters of the plaintext
% and up to three letters of the key.
%
% This implementation uses a 3x3x3 Polybius cube (27 symbols):
% the standard English alphabet A-Z plus the symbol '#'.
% Only characters A-Z and '#' are processed; other characters are ignored.
%
% Syntax: 	out=trifid(text,key,period,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the keyword used to generate the 3x3x3 Polybius cube
%                 (character array or string scalar)
%           period - an integer number used to fractionate the message.
%                    It must be less than or equal to message length
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text (processed)
%           out.key = the used key (processed)
%           out.period = the used period
%           out.encrypted = the coded text (processed)
%
% Examples:
%
% out=trifid('Hide the gold into the tree stump','leprachaun',7,1)
%
% out=trifid('AHULQISGGXEQSOKHHQFSSNRLYJJ','leprachaun',7,-1)
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares,
% nihilist, playfair, polybius, threesquares, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,period,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key);  key  = char(key);  end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% --- Filter and normalize text and key (A-Z and # only) ---
ctext = double(upper(text));
isAZ  = (ctext>=65 & ctext<=90);
isHsh = (ctext==35);
ctext = ctext(isAZ | isHsh);

ckey_raw = double(upper(key));
isAZk  = (ckey_raw>=65 & ckey_raw<=90);
isHshk = (ckey_raw==35);
ckey_raw = ckey_raw(isAZk | isHshk);

assert(~isempty(ctext),'Text must contain at least one valid character (A-Z or #).')
assert(~isempty(ckey_raw),'Key must contain at least one valid character (A-Z or #).')
assert(period <= numel(ctext), ...
    'Period must be <= message length after filtering (%d).', numel(ctext))

% Outputs (processed)
switch direction
    case 1
        out.plain = char(ctext);
    case -1
        out.encrypted = char(ctext);
end
out.key = char(ckey_raw);
out.period = period;

% --- 3x3x3 Polybius cube generation from key ---
% Start with a 27-symbol alphabet (A-Z plus '#')
A = [65:1:90 35];

% Use unique characters from the key, then fill with remaining symbols
ckey = unique(ckey_raw,'stable');
PS = [ckey A(~ismember(A,ckey))];

assert(numel(PS)==27 && numel(unique(PS))==27, ...
    'Invalid Polybius cube generation. Check the key contents.')

clear A ckey

% Coordinates matrix for the 3x3x3 cube (columns correspond to PS order)
C = [ ...
    1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 3 3 3 3 3 3 3 3 3; ...
    1 1 1 2 2 2 3 3 3 1 1 1 2 2 2 3 3 3 1 1 1 2 2 2 3 3 3; ...
    1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3 1 2 3];

% --- Convert text to cube coordinates ---
L = numel(ctext);
tmp = zeros(3,L);

for i = 1:L
    idx = find(PS==ctext(i),1);
    assert(~isempty(idx),'Text contains characters not encodable with the generated cube.')
    tmp(:,i) = C(:,idx);
end

Z = zeros(1,L);

% Number of blocks
K = ceil(L/period);
pos = 1;

% Process blocks
for b = 1:K
    H = min(size(tmp,2),period);

    switch direction
        case 1 % encrypt
            % read horizontally within the block
            tmp2 = reshape(tmp(:,1:H)',3,H);
        case -1 % decrypt
            % read vertically within the block
            tmp2 = reshape(reshape(tmp(:,1:H),3*H,1),H,3)';
    end

    tmp(:,1:H) = [];

    % Map coordinates back to symbols
    for j = 1:H
        symIdx = find(all(C==tmp2(:,j),1),1);
        assert(~isempty(symIdx),'Internal coordinate mapping error.')
        Z(pos) = PS(symIdx);
        pos = pos + 1;
    end
end

clear tmp tmp2 H b j K pos symIdx

switch direction
    case 1
        out.encrypted = char(Z);
    case -1
        out.plain = char(Z);
end

end
