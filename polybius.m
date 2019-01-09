function out=polybius(x,ms)
% POLYBIUS Cipher encoder/decoder
% In cryptography, the Polybius square, also known as the Polybius
% checkerboard, is a device invented by the Ancient Greeks Cleoxenus and
% Democleitus, and perfected by the Ancient Greek historian and scholar
% Polybius, for fractionating plaintext characters so that they can be
% represented by a smaller set of symbols. The original square used the
% Greek alphabet, but it can be used with any other alphabet. 
% With the modern English alphabet, this is the typical form: 
%
%    1   2   3   4   5
% 1  A   B   C   D   E
% 2  F   G   H  I/J  K
% 3  L   M   N   O   P
% 4  Q   R   S   T   U
% 5  V   W   X   Y   Z
%
% Each letter is then represented by its coordinates in the grid. For
% example, "BAT" becomes "12 11 44". Because 26 characters do not quite fit
% in a square, it is rounded down to the next lowest square number by
% combining two letters, usually I and J (Polybius had no such problem
% because the Greek alphabet has 24 letters). Alternatively, the ten digits
% could be added, and 36 characters would be put into a 6 × 6 grid.
%
%    1   2   3   4   5   6
% 1  A   B   C   D   E   F
% 2  G   H   I   J   K   L
% 3  M   N   O   P   Q   R
% 4  S   T   U   V   W   X
% 5  Y   Z   0   1   2   3
% 6  4   5   6   7   8   9
%
% Syntax: 	out=polybius(x,ms)
%
%     Input:
%           x - It can be a characters array or a numbers array. In first
%           case it will encoded; in the second case it will decoded. 
%           ms - this parameter can assume only two values: 
%                   5 to use a 5x5 Polybius square
%                   6 to use a 6x6 Polybius square
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.ms = the size of Polybius Square
%           out.encrypted = the coded text
%
% Examples:
% 
% out=polybius('Giuseppe Cardillo',5)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'GIUSEPPE CARDILLO'
%            ms: 5
%     encrypted: [22 24 45 43 15 35 35 15 13 11 42 14 24 31 31 34]
%
% out=polybius([22 24 45 43 15 35 35 15 13 11 42 14 24 31 31 34],5)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: [22 24 45 43 15 35 35 15 13 11 42 14 24 31 31 34]
%            ms: 5
%         plain: 'GIUSEPPECARDILLO'
%
% Many other algorithms are based onto Polybius Square.
% See also adfgx, adfgvx, bazeries, bifid, checkerboard1, checkerboard2, foursquares, nihilist, playfair, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

assert(ms==5 || ms==6,'Polybius matrix can be 5x5 or 6x6')
% rearrange ASCII codes into a square matrix
switch ms
    case 5
        %PS=ASCII CODES FOR [ABCDEFGHIKLMNOPQRSTUVWXYZ]
        PS=reshape([65:1:73 75:1:90],5,5)'; %5x5 Polybius Square
    case 6
        %PS=ASCII CODES FOR [ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]
        PS=reshape([65:1:90 48:1:57],6,6)'; %6x6 Polybius Square
end

if ischar(x) %encrypt
    % Set all letters in uppercase and convert into ASCII Code.
    out.plain=upper(x);
    text=double(out.plain);
    out.ms=ms;
    switch ms
        case 5
            % Erase all characters that are not into the range 65 - 90;
            text(text<65 | text>90)=[];
            % Convert J (ASCII code 74) into I (ASCII code 73)
            text(text==74)=73;
        case 6
            % ASCII codes for Uppercase letters ranges between 65 and 90;
            % ASCII codes for digits ranges between 48 and 57;
            % Erase all ASCII codes between 57 and 65; below 48 and above 90
            text(text>57 & text<65)=[];
            text(text<48 | text>90)=[];
    end
    % Find the index of each characters into Polybius square
    [~,locb]=ismember(text,PS);
    % transform index into subscripts
    [I,J]=ind2sub([ms,ms],locb);
    % Combine subcripts
    out.encrypted=I.*10+J;
else
    switch ms
        case 5
            assert(all(ismember(x,[11:1:15 21:1:25 31:1:35 41:1:45 51:1:55],'This array can''t be decoded using a 5x5 Polybius matrix')))
        case 6
            assert(all(ismember(x,[11:1:16 21:1:26 31:1:36 41:1:46 51:1:56 61:1:66],'This array can''t be decoded using a 6x6 Polybius matrix')))
    end
    out.encrypted=x;
    out.ms=ms;
    % From each two-digits number:
    % the first digit is the row
    I=fix(x./10);
    % the second is the column
    J=x-I.*10;
    % trasform subscripts into index
    Ind=sub2ind([ms,ms],I,J); clear I J
    % take ASCII codes from Polybius square and transform them into letters
    out.plain=char(PS(Ind));
end