function out = periodicgromark(text,key,direction,varargin)
% PERIODIC GROMARK Cipher encoder/decoder
% A variant of the Gromark cipher using:
%   - a mixed (keyed) alphabet as in classic Gromark
%   - a *periodic* numeric key (repeated) instead of a chained/Fibonacci
%     numeric stream.
%
% For each plaintext letter:
%   1. Find its position in the mixed alphabet.
%   2. Shift that position cyclically by k (numeric key digit, 0–9).
%   3. Take the resulting letter (still in the mixed alphabet) as ciphertext.
%
% The same procedure with opposite direction (sign) decrypts the text.
% Only letters A–Z are processed; all other characters are ignored.
%
% Syntax:
%   out = periodicgromark(text,key,direction,primer)
%
% Input:
%   text      - character array to encode or decode
%   key       - keyword used to generate the mixed (cipher) alphabet
%   direction - 1 to encrypt, -1 to decrypt
%   primer    - (char) string of digits '0'–'9' used as the periodic
%               numeric key; it is repeated as needed to cover the text
%
% Output:
%   out       - structure with fields:
%                 out.plain     = plaintext (A–Z only, upper case)
%                 out.encrypted = ciphertext (A–Z only, upper case)
%                 out.key       = normalized keyword (A–Z only, upper case)
%                 out.primer    = numeric key (as passed in, unchanged)
%
% Examples:
%
% out = periodicgromark('Hide the gold into the tree stump', ...
%                       'leprachaun',1,'46975')
%
%   out =
%
%     struct with fields:
%
%           plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%             key: 'LEPRACHAUN'
%          primer: '46975'
%       encrypted: 'BDOBMBLJUPYDMAGUNNAZKLPAWWU'
%
%   out = periodicgromark('BDOBMBLJUPYDMAGUNNAZKLPAWWU', ...
%                         'leprachaun',-1,'46975')
%
%   out =
%
%     struct with fields:
%
%       encrypted: 'BDOBMBLJUPYDMAGUNNAZKLPAWWU'
%             key: 'LEPRACHAUN'
%          primer: '46975'
%           plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also gromark, gronsfeld, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

% Input parsing
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'primer',[],@(x) ischar(x) && ~isempty(x));
parse(p,text,key,direction,varargin{:});
primer = p.Results.primer;
clear p

% Primer must be provided (both for encrypt and decrypt)
assert(~isempty(primer), ...
    'Primer (numeric key) is required and must be a non-empty string of digits.');
assert(all(primer>='0' & primer<='9'), ...
    'Primer must contain only digits 0–9.');

% Normalize text and key to A–Z (ASCII 65–90)
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ckey  = double(upper(key));
ckey(ckey<65 | ckey>90) = [];

switch direction
    case 1 % encrypt
        out.plain = char(ctext);
    case -1 % decrypt
        out.encrypted = char(ctext);
end
out.key    = char(ckey);
out.primer = primer;

% Build mixed alphabet (cipher alphabet) as in Gromark:
%   - take unique letters of key (in order of appearance)
%   - append remaining letters A–Z
%   - place them into a C-by-R matrix (C = length of unique key)
%   - columnar transpose according to key order
%   - read out column-wise to get final 26-letter mixed alphabet PS
ckey = unique(ckey,'stable');
A    = 65:90;
C    = length(ckey);
R    = ceil(26/C);
pad  = R*C - 26;

B = [ckey A(~ismember(A,ckey)) zeros(1,pad)];
tmp = reshape(B,[C,R]);   % C x R, column-major
mat = tmp.';              % R x C

[~,Idx] = sort(ckey);
mat     = mat(:,Idx);     % reorder columns by key
PS      = reshape(mat,1,[]); % read column-wise
PS(PS==0) = [];
clear A B C R pad tmp mat Idx

% Build periodic numeric key stream from primer
digitsKey = double(primer) - 48; % 0–9
LT = length(ctext);
RL = ceil(LT/numel(digitsKey));
s  = repmat(digitsKey,1,RL);
s  = s(1:LT);

% Core periodic Gromark transformation
tmp = zeros(1,LT);
for I = 1:LT
    % position of current letter in mixed alphabet (1..26)
    x = find(PS==ctext(I),1,'first');
    % cyclic shift by s(I) positions (sign given by direction)
    tmp(I) = PS(mod((x-1) + direction*s(I),26) + 1);
end
clear I x LT s digitsKey

switch direction
    case 1 % encrypt
        out.encrypted = char(tmp);
    case -1 % decrypt
        out.plain = char(tmp);
end
clear tmp ctext PS
