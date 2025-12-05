function out=bifid(text,key,period,direction)
% BIFID Cipher encoder/decoder
% Bifid is a cipher which combines the Polybius square with transposition,
% and uses fractionation to achieve diffusion. It was invented by Felix
% Delastelle.
%
% English, 26 letters, alphabet is used with I/J combined.
% Only letters A-Z are processed; other characters are ignored.
% J is merged into I.
%
% Syntax: 	out=bifid(text,key,period,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key - It is the keyword used to generate Polybius Square
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
% out=bifid('Hide the gold into the tree stump','leprachaun',7,1)
%
% out=bifid('TGZAPSFFAUKMKBQKKEUSXETMSUP','leprachaun',7,-1)
%
% See also adfgx, adfgvx, checkerboard1, checkerboard2, cmbifid,
% foursquares, nihilist, playfair, polybius, threesquares, trifid,
% twosquares
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

% --- Filter and normalize text and key (A-Z only, J->I) ---
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==74) = 73;

ckey_raw = double(upper(key));
ckey_raw(ckey_raw>90 | ckey_raw<65) = [];
ckey_raw(ckey_raw==74) = 73;

assert(~isempty(ctext),'Text must contain at least one valid letter A-Z.')
assert(~isempty(ckey_raw),'Key must contain at least one valid letter A-Z.')
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

% --- Polybius square generation from key (spiral layout) ---
ckey = unique(ckey_raw,'stable');
A = [65:1:73 75:1:90]; % alphabet without J
B = [ckey A(~ismember(A,ckey))];

% Rearrange into the square in a clockwise spiral.
PS = B(fliplr(abs(spiral(5)-26)));

clear A B ckey

% --- Convert text to Polybius coordinates ---
[~,locb] = ismember(ctext,PS);
assert(all(locb>0),'Text contains characters not encodable with the generated Polybius square.')

[I,J] = ind2sub([5,5],locb);
K = numel(I);

switch direction
    case 1 % encrypt
        % Build ciphertext coordinates block by block (no padding)
        Ic = zeros(1,K);
        Jc = zeros(1,K);

        for s = 1:period:K
            idx = s:min(s+period-1,K);

            rows = I(idx);
            cols = J(idx);

            seq = [rows cols];          % 1 x (2r), rows then cols
            Rc = seq(1:2:end);
            Cc = seq(2:2:end);

            Ic(idx) = Rc;
            Jc(idx) = Cc;
        end

        Ind = sub2ind([5,5],Ic,Jc);
        out.encrypted = char(PS(Ind));

        clear Ic Jc rows cols seq Rc Cc idx r s Ind

    case -1 % decrypt
        % Ciphertext coordinates are I,J (from out.encrypted filtered)
        Ic = I;
        Jc = J;

        Ip = zeros(1,K);
        Jp = zeros(1,K);

        for s = 1:period:K
            idx = s:min(s+period-1,K);
            r = numel(idx);

            Rc = Ic(idx);
            Cc = Jc(idx);

            seq = zeros(1,2*r);
            seq(1:2:end) = Rc;
            seq(2:2:end) = Cc;

            Ip(idx) = seq(1:r);
            Jp(idx) = seq(r+1:end);
        end

        Ind = sub2ind([5,5],Ip,Jp);
        out.plain = char(PS(Ind));

        clear Ic Jc Ip Jp Rc Cc seq idx r s Ind
end

end
