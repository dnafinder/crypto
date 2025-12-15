function out=cct(text,key,direction)
% COMPLETE COLUMNAR TRANSPOSITION Cipher encoder/decoder
% Simple encoder by which the plain text is written into a rectangular
% block by filling each row and taken out by columns in order of the key.
%
% Only letters A-Z are processed; other characters are ignored.
%
% pt=filled block
% key=3 1 2
%
% 3 1 2       1 2 3
% f i l       i l f
% l e d       e d l
% b l o       l o b
% c k x       k x c
%
% ct=IELK LDOX FLBC.
%
% Syntax: 	out=cct(text,key,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the numeric array for transposition
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.encrypted = the coded text
%
% Notes:
%   During decryption, removal of padding 'X' is heuristic and may remove
%   real 'X' letters in some edge cases.
%
% Examples:
%
% out=cct('Hide the gold into the tree stump',[3 4 1 2],1)
%
% out=cct('DEDOTSPEGITRTXHTONHEUIHLTEEM',[3 4 1 2],-1)
%
% See also incompletecct
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'}, ...
    {'row','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

if isstring(text)
    text = char(text);
end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

M = max(key);
[skey,Idx] = sort(key);
assert(isequal(skey,1:M), ...
    'Key must be a permutation of 1:%d with no repeats.', M)
clear skey

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext = char(ctext);

LT = numel(ctext);
assert(LT>0,'Text must contain at least one valid letter A-Z.')

RL = ceil(LT/M);

if mod(LT,M) ~= 0
    pad = repmat('X',1,RL*M-LT);
    ctext = reshape([ctext pad],M,[])';
    clear pad
else
    switch direction
        case 1 % encrypt
            ctext = reshape(ctext,M,[])';
        case -1 % decrypt
            ctext = reshape(ctext,[],M);
    end
end
clear LT M RL

switch direction
    case 1 % encrypt
        out.plain = text;
        out.key = key;
        out.encrypted = reshape(ctext(:,Idx),1,[]);
    case -1 % decrypt
        out.encrypted = text;
        out.key = key;

        ctext = reshape(ctext(:,key)',1,[]);
        X = find(ctext=='X');
        if ~isempty(X)
            X(X==1) = []; % If "X" is the first letter, surely it wasn't added;
            c = ~ismember(ctext(X-1),'AEIOUY');
            ctext(X(c)) = [];
            clear c
        end
        clear X

        out.plain = ctext;
end

clear Idx ctext

end
